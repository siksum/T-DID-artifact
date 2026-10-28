"""Recompute per-block quantiles and paired effects from raw product HTTP records."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics


def rows(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def q(values, p):
    v=sorted(values);t=(len(v)-1)*p;i=int(t)
    return v[i]+(v[min(i+1,len(v)-1)]-v[i])*(t-i)


def main():
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--out',type=Path,required=True);p.add_argument('--partial',action='store_true');a=p.parse_args()
    a.out.mkdir(parents=True,exist_ok=True)
    blocks=[];requests=[];files={}
    for b in sorted(a.root.glob('*-pair*-*')):
        if not (b/'completion.json').exists():continue
        product=b.name.split('-pair')[0];pair=int(b.name.split('-pair')[1].split('-')[0]);mode=b.name.rsplit('-',1)[1]
        assert json.loads((b/'validation.json').read_text())['passed']
        sub=b/('waltid' if product=='waltid' else 'credo')
        cases=rows(sub/('case-design.jsonl' if product=='waltid' else 'case-metrics.jsonl'))
        measured=[c for c in cases if c['phase']=='measured'];assert len(measured)==100,(b,len(measured))
        case_lookup={c['case_id']:c for c in measured}
        http=rows(sub/'http.jsonl')
        selected=[]
        for r in http:
            case=r.get('case') if product=='waltid' else r.get('case_id')
            credential=r.get('label')=='issuer.credential' if product=='waltid' else r['path'].endswith('/credential')
            if case in case_lookup and credential:
                ms=r['elapsed_ns']/1e6
                selected.append(ms)
                requests.append(dict(product=product,pair=pair,mode=mode,case_id=case,scenario=case_lookup[case]['scenario'],status=r['status'],elapsed_ms=ms))
        assert len(selected)==180,(b,len(selected))
        total_bytes=sum(c['event_bytes'] for c in measured)
        blocks.append(dict(product=product,pair=pair,mode=mode,cases=100,requests=len(selected),p50_ms=q(selected,.5),p95_ms=q(selected,.95),
            event_bytes=total_bytes,bytes_per_case=total_bytes/100,events_per_case=1.8 if mode=='on' else 0))
        for f in sorted(b.rglob('*')):
            if f.is_file():files[str(f.relative_to(a.root))]=hashlib.sha256(f.read_bytes()).hexdigest()
    if not a.partial:assert len(blocks)==40,len(blocks)
    summary={};pairs=[]
    for product in ['waltid','credo']:
        bs=[b for b in blocks if b['product']==product]
        if not bs:continue
        modes={}
        for mode in ['off','on']:
            xs=[b for b in bs if b['mode']==mode]
            if not xs:continue
            modes[mode]={k:{'median':statistics.median([x[k] for x in xs]),'min':min(x[k] for x in xs),'max':max(x[k] for x in xs)} for k in ['p50_ms','p95_ms','bytes_per_case','events_per_case']}
        ps=[]
        for i in sorted({b['pair'] for b in bs}):
            z={b['mode']:b for b in bs if b['pair']==i}
            if len(z)!=2:continue
            r={'product':product,'pair':i,'first':'off' if i%2==0 else 'on'}
            for metric in ['p50_ms','p95_ms']:
                r[metric+'_delta']=z['on'][metric]-z['off'][metric]
                r[metric+'_percent']=100*r[metric+'_delta']/z['off'][metric]
            pairs.append(r);ps.append(r)
        paired={k:{'median':statistics.median([x[k] for x in ps]),'min':min(x[k] for x in ps),'max':max(x[k] for x in ps)} for k in ['p50_ms_delta','p50_ms_percent','p95_ms_delta','p95_ms_percent']} if ps else {}
        summary[product]={'blocks':len(bs),'pairs':len(ps),'modes':modes,'paired':paired}
    for name,data in [('requests',requests),('blocks',blocks),('pairs',pairs)]:
        if data:
            with (a.out/f'{name}.csv').open('w') as f:
                w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)
    (a.out/'summary.json').write_text(json.dumps({'complete':len(blocks)==40,'summary':summary,'blocks':blocks,'pairs':pairs},indent=2)+'\n')
    (a.out/'SHA256SUMS.json').write_text(json.dumps(files,indent=2)+'\n')
    print(json.dumps(summary,indent=2))


if __name__=='__main__':main()
