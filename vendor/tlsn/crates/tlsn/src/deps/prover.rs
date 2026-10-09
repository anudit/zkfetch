use mpc_tls::{MpcTlsLeader, SessionKeys};
use mpz_common::{Context, ContextId};
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_ot::{
    chou_orlandi as co, kos,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use std::sync::Arc;
use tlsn_core::{
    config::tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    connection::TlsVersion,
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    Error,
    deps::{build_mpc_tls_config, translate_keys},
    proxy::{AnyProxyProver, ProxyProver, ProxyProver13},
};

cfg_select! {
    tlsn_insecure => {
        pub(crate) type ProverMpc = mpz_ideal_vm::IdealVm;
        pub(crate) type ProverZk = mpz_ideal_vm::IdealVm;
    }
    _ => {
        use mpz_garble::protocol::semihonest::Garbler;
        use mpz_ot::cot::DerandCOTSender;
        use mpz_zk::Prover;
        use rand::Rng;

        pub(crate) type ProverMpc =
            Garbler<DerandCOTSender<SharedRCOTSender<kos::Sender<co::Receiver>, Block>>>;
        pub(crate) type ProverZk =
            Prover<SharedRCOTReceiver<crate::vole_pool::PooledReceiver, bool, Block>>;
    }
}

/// Protocol dependencies for MPC.
pub(crate) struct ProverMpcDeps {
    pub(crate) vm: Arc<Mutex<Deap<ProverMpc, ProverZk>>>,
    pub(crate) mpc_tls: Box<MpcTlsLeader>,
    pub(crate) keys: Option<SessionKeys>,
}

impl std::fmt::Debug for ProverMpcDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProverMpcDeps").finish_non_exhaustive()
    }
}

impl ProverMpcDeps {
    pub(crate) fn new(config: &MpcTlsConfig, ctx: Context) -> Self {
        let mut rng = rand::rng();
        let delta = Delta::new(Block::random(&mut rng));

        let base_ot_recv = co::Receiver::default();
        let rcot_send = kos::Sender::new(
            kos::SenderConfig::default(),
            delta.into_inner(),
            base_ot_recv,
        );
        let pool = crate::vole_pool::ProverVolePool::new([0; 32]);
        let rcot_recv = pool.receiver();

        let rcot_send = SharedRCOTSender::new(rcot_send);
        let rcot_recv = SharedRCOTReceiver::new(rcot_recv);

        let mpc = cfg_select! {
            tlsn_insecure => { mpz_ideal_vm::IdealVm::new() }
            _ => {
                ProverMpc::new(DerandCOTSender::new(rcot_send.clone()), rng.random(), delta)
            }
        };

        let zk = cfg_select! {
            tlsn_insecure => { mpz_ideal_vm::IdealVm::new() }
            _ => { ProverZk::new(Default::default(), rcot_recv.clone()) }
        };

        let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Leader, mpc, zk)));
        let mpc_tls = MpcTlsLeader::new(
            build_mpc_tls_config(config),
            ctx,
            vm.clone(),
            (rcot_send.clone(), rcot_send.clone(), rcot_send),
            rcot_recv,
        );

        Self {
            vm,
            mpc_tls: Box::new(mpc_tls),
            keys: None,
        }
    }

    pub(crate) async fn setup(&mut self) -> Result<(), Error> {
        let mut keys = self.mpc_tls.alloc().map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed to allocate mpc-tls resources")
                .with_source(e)
        })?;
        let vm_lock = self.vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock);
        self.keys = Some(keys);

        drop(vm_lock);

        debug!("setting up mpc-tls");
        self.mpc_tls.preprocess().await.map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed during mpc-tls preprocessing")
                .with_source(e)
        })?;

        Ok(())
    }
}

/// Protocol dependencies for Proxy.
pub(crate) struct ProverProxyDeps {
    pub(crate) pipeline_tls: bool,
    pub(crate) prover: Box<AnyProxyProver>,
    pub(crate) id: ContextId,
}

impl std::fmt::Debug for ProverProxyDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProverProxyDeps").finish_non_exhaustive()
    }
}

impl ProverProxyDeps {
    pub(crate) fn new(
        config: &ProxyTlsConfig,
        ctx: Context,
        pool: Option<&crate::vole_pool::ProverVolePool>,
    ) -> Self {
        let mut vm = cfg_select! {
            tlsn_insecure => { mpz_ideal_vm::IdealVm::new() }
            _ => {{
                let fresh;
                let pool = match pool { Some(pool) => pool, None => { fresh = crate::vole_pool::ProverVolePool::new([0; 32]); &fresh } };
                let rcot_recv = SharedRCOTReceiver::new(pool.receiver());
                ProverZk::new(Default::default(), rcot_recv)
            }}
        };

        if let Some(pool) = pool.filter(|p| p.low_latency) {
            vm.bind_statement(&pool.binding);
            vm.bind_statement(&bincode::serialize(config).expect("serializable proxy config"));
        }
        let id = ctx.id().to_owned();
        let prover = match config.tls_version() {
            TlsVersion::V1_2 => AnyProxyProver::V12(ProxyProver::new(vm, ctx)),
            TlsVersion::V1_3 => AnyProxyProver::V13(ProxyProver13::new(
                vm,
                ctx,
                pool.is_some_and(|p| p.low_latency),
                pool.and_then(|p| p.ready.clone()),
                pool.and_then(|p| p.begin_proof.clone()),
            )),
        };

        Self {
            pipeline_tls: pool.is_some_and(|p| p.pipeline_tls),
            prover: Box::new(prover),
            id,
        }
    }

    pub(crate) async fn setup(&mut self) -> Result<(), Error> {
        self.prover.alloc()?;

        debug!("setting up proxy-tls");
        if !self.pipeline_tls {
            self.prover.preprocess().await?;
        }

        Ok(())
    }
}
