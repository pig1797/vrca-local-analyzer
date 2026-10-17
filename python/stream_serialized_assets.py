"""Read-only UnityFS extraction of serialized entries, skipping resource streams.
Development tool, not a repacker. Never writes the input file.
"""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vrca_memory_guard import apply_windows_memory_limit
apply_windows_memory_limit()
import lz4.block
MAX_BLOCK_BYTES = 128*1024*1024


def exact(stream, count):
    data = stream.read(count)
    if len(data) != count: raise ValueError("truncated bundle")
    return data


def number(stream, fmt): return struct.unpack(fmt, exact(stream, struct.calcsize(fmt)))[0]


def cstring(stream, limit=4096):
    data = bytearray()
    for _ in range(limit):
        value = exact(stream, 1)
        if value == b"\0": return data.decode("utf-8", "strict")
        data.extend(value)
    raise ValueError("oversized string")


def decompress(data, size, flags):
    if size > MAX_BLOCK_BYTES: raise ValueError("single block exceeds safe probe limit")
    kind = flags & 63
    if kind == 0: out = data
    elif kind in (2,3): out = lz4.block.decompress(data, uncompressed_size=size)
    elif kind == 1:
        props, dictionary = struct.unpack("<BI", data[:5])
        if dictionary > 64*1024*1024: raise ValueError("LZMA dictionary too large")
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1,
            "dict_size": dictionary, "lc": props%9, "lp": (props//9)%5, "pb": props//45}])
        out = decoder.decompress(data[5:], max_length=size+1)
    else: raise ValueError("unsupported block compression")
    if len(out) != size: raise ValueError("decompression size mismatch")
    return out


def inspect(source):
    with source.open("rb") as stream:
        if cstring(stream,32) != "UnityFS": raise ValueError("not UnityFS")
        version = number(stream, ">I")
        player, engine = cstring(stream,128), cstring(stream,128)
        declared = number(stream, ">Q")
        compressed, uncompressed, flags = (number(stream, ">I") for _ in range(3))
        if version < 7 or declared != source.stat().st_size or flags & 0x1400:
            raise ValueError("unsupported header/encryption/size")
        if max(compressed,uncompressed)>16*1024*1024: raise ValueError("oversized block table")
        start = (stream.tell()+15)//16*16
        stream.seek(declared-compressed if flags & 0x80 else start)
        metadata = io.BytesIO(decompress(exact(stream,compressed),uncompressed,flags))
        exact(metadata,16)
        count = number(metadata,">I")
        if count>100000: raise ValueError("too many blocks")
        blocks=[struct.unpack(">IIH",exact(metadata,10)) for _ in range(count)]
        node_count=number(metadata,">I")
        if node_count>10000: raise ValueError("too many entries")
        nodes=[]
        for index in range(node_count):
            offset,size,entry_flags=struct.unpack(">QQI",exact(metadata,20))
            name=cstring(metadata)
            if offset+size>sum(b[0] for b in blocks): raise ValueError("entry outside data")
            nodes.append({"index":index,"offset":offset,"size":size,"flags":entry_flags,"name":name})
        data_start = start if flags&0x80 else start+compressed
        if flags&0x200: data_start=(data_start+15)//16*16
        if data_start+sum(b[1] for b in blocks)>declared-(compressed if flags&0x80 else 0):
            raise ValueError("block data outside file")
        return {"version":version,"player":player,"engine":engine,"flags":flags,
            "size":declared,"expanded_size":sum(b[0] for b in blocks),"blocks":blocks,
            "data_start":data_start,"nodes":nodes}


def main():
    global MAX_BLOCK_BYTES
    sys.stdout.reconfigure(encoding="utf-8")
    p=argparse.ArgumentParser();p.add_argument("input",type=Path);p.add_argument("--output",type=Path)
    p.add_argument("--max-block-mb",type=int,choices=(128,256),default=128)
    args=p.parse_args(); MAX_BLOCK_BYTES=args.max_block_mb*1024*1024; info=inspect(args.input)
    if args.output:
        args.output.mkdir(parents=True,exist_ok=True)
        selected=[n for n in info["nodes"] if not n["name"].lower().endswith((".ress",".resource"))]
        outputs=[]
        for n in selected:
            if n["size"]>512*1024*1024: raise ValueError("serialized entry too large")
            path=args.output/f"serialized-{n['index']:03d}.assets"
            if path.exists(): raise ValueError("refusing to overwrite extracted entry")
            outputs.append((n,path,path.with_suffix(".assets.partial").open("xb"),hashlib.sha256(),0))
        try:
            with args.input.open("rb") as stream:
                stream.seek(info["data_start"]); offset=0
                for size,compressed,flags in info["blocks"]:
                    needed=any(n["offset"]<offset+size and n["offset"]+n["size"]>offset for n in selected)
                    if needed:
                        if compressed>128*1024*1024: raise ValueError("compressed block exceeds probe limit")
                        data=decompress(exact(stream,compressed),size,flags)
                        for i,(n,path,out,sha,total) in enumerate(outputs):
                            lo=max(offset,n["offset"]);hi=min(offset+size,n["offset"]+n["size"])
                            if hi>lo:
                                part=data[lo-offset:hi-offset];out.write(part);sha.update(part)
                                outputs[i]=(n,path,out,sha,total+len(part))
                    else: stream.seek(compressed,1)
                    offset+=size
            for n,path,out,sha,total in outputs:
                if total!=n["size"]: raise ValueError("incomplete serialized extraction")
                n["extracted_path"]=str(path);n["sha256"]=sha.hexdigest()
        finally:
            for _,_,out,_,_ in outputs:out.close()
        for _,path,_,_,_ in outputs:
            path.with_suffix(".assets.partial").rename(path)
        (args.output/"bundle-layout.json").write_text(json.dumps(info,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({k:v for k,v in info.items() if k!="blocks"},ensure_ascii=False))


if __name__=="__main__":main()
