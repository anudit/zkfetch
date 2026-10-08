#!/usr/bin/env python3
"""Resolve samply Rust stacks and emit CPU-weighted flamegraphs and hotspot data.

Start `samply load --no-open PROFILE`, then pass its printed symbolServer URL.
For xctrace time-profile XML, also pass --symbol-profile with a samply capture
of the same binary. Instruments supplies on-CPU samples; samply supplies CPU
deltas (which can attribute preceding work to a subsequent blocked stack).
"""

import argparse
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import urllib.request
import xml.etree.ElementTree as ET


def resolve(profile, addresses, server):
    addresses = sorted(addresses)
    request = {"jobs": [{
        "memoryMap": [[lib["debugName"], lib["breakpadId"]] for lib in profile["libs"]],
        "stacks": [[list(address)] for address in addresses],
    }]}
    response = json.load(urllib.request.urlopen(urllib.request.Request(
        server.rstrip("/") + "/symbolicate/v5", data=json.dumps(request).encode(),
        headers={"Content-Type": "application/json"}), timeout=120))
    return {address: frames[-1].get("function", "?")
            for address, frames in zip(addresses, response["results"][0]["stacks"]) if frames}


def samply_stacks(profile, server):
    addresses = set()
    for thread in profile["threads"]:
        for address, func in zip(thread["frameTable"]["address"], thread["frameTable"]["func"]):
            resource = thread["funcTable"]["resource"][func]
            lib = thread["resourceTable"]["lib"][resource] if resource >= 0 else None
            if lib is not None:
                addresses.add((lib, address))
    names = resolve(profile, addresses, server)
    folded = Counter()
    for thread in profile["threads"]:
        frames = thread["frameTable"]
        funcs = thread["funcTable"]
        stacks = thread["stackTable"]
        cache = {None: ()}

        def chain(index):
            if index not in cache:
                frame = stacks["frame"][index]
                func = frames["func"][frame]
                resource = funcs["resource"][func]
                lib = thread["resourceTable"]["lib"][resource] if resource >= 0 else None
                name = names.get((lib, frames["address"][frame]),
                                 thread["stringArray"][funcs["name"][func]])
                cache[index] = chain(stacks["prefix"][index]) + (name,)
            return cache[index]

        for stack, weight in zip(thread["samples"]["stack"], thread["samples"]["threadCPUDelta"]):
            if stack is not None and weight is not None and weight > 0:
                folded[(thread["name"],) + chain(stack)] += weight
        # Make the saved profile self-contained for offline Firefox Profiler use.
        for frame, func in enumerate(frames["func"]):
            resource = funcs["resource"][func]
            lib = thread["resourceTable"]["lib"][resource] if resource >= 0 else None
            name = names.get((lib, frames["address"][frame]))
            if name:
                funcs["name"][func] = len(thread["stringArray"])
                thread["stringArray"].append(name)
    profile["meta"]["symbolicated"] = True
    return folded


def xctrace_stacks(path, profile, server):
    root = ET.parse(path).getroot()
    ids = {node.attrib["id"]: node for node in root.iter() if "id" in node.attrib}

    def deref(node):
        return ids[node.attrib["ref"]] if "ref" in node.attrib else node

    lib_ids = {lib["codeId"].upper(): i for i, lib in enumerate(profile["libs"])}
    frame_addresses = {}
    for node in root.iter("frame"):
        node = deref(node)
        binary_node = node.find("binary")
        if binary_node is None:
            continue
        binary = deref(binary_node)
        uuid = binary.attrib["UUID"].replace("-", "").upper()
        if uuid in lib_ids:
            frame_addresses[node.attrib["id"]] = (
                lib_ids[uuid], int(node.attrib["addr"], 16) - int(binary.attrib["load-addr"], 16))
    names = resolve(profile, set(frame_addresses.values()), server)
    folded = Counter()
    for row in root.iter("row"):
        if deref(row.find("thread-state")).text != "Running":
            continue
        backtrace = row.find("tagged-backtrace")
        if backtrace is None:
            continue
        thread = deref(row.find("thread")).attrib["fmt"].split(" (")[0]
        frames = [deref(frame) for frame in deref(backtrace)]
        chain = tuple(names.get(frame_addresses.get(frame.attrib["id"]), frame.attrib.get("name", "[unknown]"))
                      for frame in reversed(frames))
        folded[(thread,) + chain] += int(deref(row.find("weight")).text) / 1000
    return folded


def svg(folded, path, title):
    tree = {"weight": 0, "children": {}}
    for stack, weight in folded.items():
        node = tree
        node["weight"] += weight
        previous = None
        for name in stack:
            if name == previous:
                continue
            previous = name
            node = node["children"].setdefault(name, {"weight": 0, "children": {}})
            node["weight"] += weight
    total = tree["weight"] or 1
    width = 1600
    def visible_depth(node):
        return 1 + max((visible_depth(child) for child in node["children"].values()
                        if child["weight"] / total * (width - 30) >= 0.4), default=0)
    height = 80 + 18 * visible_depth(tree)
    elements = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
                f'viewBox="0 0 {width} {height}"><style>text{{font:11px monospace;pointer-events:none}}'
                'rect:hover{stroke:black;stroke-width:1.5}</style>',
                f'<rect width="{width}" height="{height}" fill="#faf8f3"/>',
                f'<text x="15" y="24">{html.escape(title)}</text>',
                '<text x="15" y="44">Width = sampled CPU weight; hover for full names and percentages.</text>']

    def draw(node, x, level, name):
        span = node["weight"] / total * (width - 30)
        if span < 0.4:
            return
        y = height - 25 - level * 18
        color = hashlib.sha256(name.encode()).digest()
        fill = f'rgb({210 + color[0] % 45},{110 + color[1] % 100},{65 + color[2] % 90})'
        label = f'{name}: {node["weight"] / 1000:.2f} ms ({node["weight"] / total * 100:.2f}%)'
        elements.append(f'<g><title>{html.escape(label)}</title><rect x="{x:.3f}" y="{y}" '
                        f'width="{span:.3f}" height="17" fill="{fill}"/>')
        if span >= 35:
            short = name[:max(1, int(span / 6.7) - 2)]
            elements.append(f'<text x="{x + 3:.3f}" y="{y + 12}">{html.escape(short)}</text>')
        elements.append('</g>')
        for child_name, child in sorted(node["children"].items()):
            draw(child, x, level + 1, child_name)
            x += child["weight"] / total * (width - 30)

    draw(tree, 15, 0, "all sampled CPU")
    elements.append('</svg>')
    path.write_text("\n".join(elements))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--symbol-server", required=True)
    parser.add_argument("--symbol-profile", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    profile = json.loads((args.symbol_profile or args.profile).read_text())
    if args.symbol_profile:
        folded = xctrace_stacks(args.profile, profile, args.symbol_server)
        source = "Instruments running-thread CPU samples, weights in microseconds"
    else:
        folded = samply_stacks(profile, args.symbol_server)
        args.out.with_suffix(".symbolicated.json").write_text(json.dumps(profile))
        source = "samply CPU deltas, weights in microseconds; blocked-stack attribution is approximate"
    leaf, inclusive = Counter(), Counter()
    for stack, weight in folded.items():
        leaf[stack[-1]] += weight
        inclusive.update(dict.fromkeys(stack, weight))
    total = sum(folded.values())
    data = {"source": source, "sampledCpuMs": total / 1000,
            "leaf": leaf.most_common(), "inclusive": inclusive.most_common()}
    args.out.with_suffix(".hotspots.json").write_text(json.dumps(data, indent=2))
    args.out.with_suffix(".folded").write_text("\n".join(
        ";".join(name.replace(";", ",") for name in stack) + f" {round(weight)}"
        for stack, weight in folded.items()))
    svg(folded, args.out.with_suffix(".svg"), args.out.name)
    reversed_stacks = Counter()
    for stack, weight in folded.items():
        reversed_stacks[tuple(reversed(stack))] += weight
    svg(reversed_stacks, args.out.with_suffix(".reversed.svg"), args.out.name + " — leaf functions first")
    for name, weight in leaf.most_common(15):
        print(f"{100 * weight / total:5.1f}% {name}")


if __name__ == "__main__":
    main()
