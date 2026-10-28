"""Build the follow-up report and manuscript replacement from saved measurements."""
from __future__ import annotations

import csv
import gzip
import json
import os
import statistics as st
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'results'
RAW = OUT / 'data/cost_followup'


def jsonlines(name):
    return [json.loads(x) for x in (RAW / name).read_text().splitlines() if x.startswith('{')]


def stats(values):
    return dict(median=st.median(values), min=min(values), max=max(values))


def format_range(s, digits=3):
    return f"{s['median']:.{digits}f} [{s['min']:.{digits}f}, {s['max']:.{digits}f}]"


def harness_pct(values, q):
    k = (len(values) - 1) * q / 100
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def main():
    rows = list(csv.DictReader((RAW / 'latency_summary.csv').open()))
    latency = defaultdict(lambda: defaultdict(list))
    for r in rows:
        latency[r['judge']][int(float(r['load']))].append(float(r['p95_ms']))
    latency = {j: {str(load): stats(v) for load, v in d.items()} for j, d in latency.items()}
    stages = jsonlines('stages.jsonl')
    stage_summary = {}
    for count in (1, 21):
        timed = [r for r in stages if r['rules'] == count and r['instrumented']]
        normal = [r for r in stages if r['rules'] == count and not r['instrumented']]
        events = sum(r['events'] for r in timed)
        pooled = {k: sum(r['ns'][k] for r in timed) / events / 1000
                  for k in timed[0]['ns']}
        stage_summary[str(count)] = dict(us_per_event=pooled,
            normal_us_per_event=stats([r['us_per_event']['processing'] for r in normal]),
            instrumented_us_per_event=stats([r['us_per_event']['processing'] for r in timed]),
            rule_calls_per_event=sum(r['calls']['rule_evaluate'] for r in timed) / events)
    state = jsonlines('state.jsonl')
    assert len(state) == 30
    assert all(r['state_entries'] == r['n_proofs'] and r['gate_seen_ids'] == r['accepted_events'] for r in state)
    heap = jsonlines('heap.jsonl') if (RAW / 'heap.jsonl').exists() else []
    old = jsonlines('prior_memprobe.jsonl')
    old100 = next(r for r in old if r['n_proofs'] == 100000 and r['heap_growth_kib'] is not None)
    fig3 = json.loads((OUT / 'data/fig3.json').read_text())
    memory = fig3['memory_mib']['tdid']
    old_latency = {j: {load: {k: v * 1000 for k, v in s.items()} for load, s in d.items()}
                   for j, d in fig3['p95_s'].items()}
    summary = dict(latency_ms=latency, stages=stage_summary, original_latency_ms=old_latency,
                   memory_curve_mib=memory, heap_probes=heap, prior_100k_heap_probe=old100,
                   state_cells_checked=len(state), state_entry_invariants=True)
    last = {}
    event_path = Path(os.environ.get('TDID_COST_FOLLOWUP_EVENTS', str(RAW / 'latency_events.jsonl')))
    if not event_path.exists():
        event_path = Path(json.loads((RAW / 'environment.json').read_text())['event_records_gzip'])
    opener = gzip.open if event_path.suffix == '.gz' else open
    with opener(event_path, 'rt') as f:
        for line in f:
            r = json.loads(line)
            last[(r['judge'], float(r['load']), r['repeat'], r['run'])] = r
    timing_cells = defaultdict(lambda: defaultdict(list))
    partition_error = 0.0
    for (judge, load, repeat, run), r in last.items():
        if float(r['scheduled_ms']) < 1000 or r['read_ms'] == '':
            continue
        a = float(r['written_ms']) - float(r['scheduled_ms'])
        b = float(r['read_ms']) - float(r['written_ms'])
        partition_error = max(partition_error, abs(a + b - float(r['latency_ms'])))
        cell = timing_cells[(judge, load, repeat)]
        cell['sender_late_ms'].append(a)
        cell['start_to_read_ms'].append(b)
        cell['total_ms'].append(float(r['latency_ms']))
    timing = []
    for (judge, load, repeat), d in timing_cells.items():
        timing.append(dict(judge=judge, load=load, repeat=repeat,
                           **{k: harness_pct(sorted(v), 95) for k, v in d.items()}))
    summary['timing_partition_max_rounding_error_ms'] = partition_error
    summary['timing_p95_by_repeat'] = timing
    (RAW / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    lines = ['# 보완 측정 결과', '', '수치는 저장 원자료에서 생성했다. 대괄호는 반복의 최솟값과 최댓값이며 신뢰구간이 아니다.', '',
             '## 같은 발급 부하의 지연', '', 'p95의 반복 중앙값 [최소, 최대], ms. 5초 창, 앞 1초 제외, 각 칸 5회. 모든 규칙을 켠 조건도 THR-015 발급 입력만 사용했다.', '',
             '| 부하 runs/s | 규칙 1개 | 규칙 21개 | 판정기 없음 |', '|---:|---:|---:|---:|']
    for load in ('1000', '2000'):
        lines.append(f"| {load} | " + ' | '.join(format_range(latency[j][load]) for j in ('tdid', 'tdid_all', 'echo')) + ' |')
    lines += ['', '## 실제 경로의 시간 분해', '',
              '각 반복의 총 소요시간을 전체 사건 수로 나눈 뒤, 5회 사건을 합산한 평균이다. 단위 µs/event. 입력 검사는 Gate 전체(프로필·스키마·불변식·지문·중복 및 순서 관리)를 뜻한다. 규칙 평가는 상태 조회를 포함하고, 상태 저장은 commit만 포함한다. 기타는 View와 Finding 생성, dispatch 및 타이머 호출 비용을 포함한다. JSON 생성과 직렬화, 파이프 전송은 제외한다.', '',
              '| 구간 | 규칙 1개 | 규칙 21개 |', '|---|---:|---:|']
    for label, key in [('JSON 읽기', 'parse'), ('입력 검사와 접수', 'gate'), ('규칙 평가', 'rule_evaluate'),
                       ('상태 저장', 'commit'), ('기타 엔진 처리', 'other_engine'), ('계측 합계', 'processing')]:
        lines.append(f"| {label} | {stage_summary['1']['us_per_event'][key]:.2f} | {stage_summary['21']['us_per_event'][key]:.2f} |")
    lines += ['', '| 무계측 처리 µs/event | 중앙값 [최소, 최대] |', '|---|---:|']
    for count in ('1', '21'):
        lines.append(f"| 규칙 {count}개 | {format_range(stage_summary[count]['normal_us_per_event'], 2)} |")
    lines += ['', '규칙 평가 호출은 사건당 각각 1회와 6회였다. 계측 여부와 활성 규칙 수가 달라도 THR-015 사건별 판정의 해시는 시드 5개 모두 같았다. 계측 합계는 타이머 오버헤드를 포함한 진단값이며 운영 지연은 위의 별도 무계측 스트리밍 측정으로 판단한다.', '',
              '## 메모리 증가', '', '| 고유 증명 수 | 규칙 1개 최대 상주 메모리 MiB |', '|---:|---:|']
    for n in ('10', '1000', '10000'):
        lines.append(f"| {n} | {format_range(memory[n], 2)} |")
    lines += ['', '그림은 기존 스트리밍 판정기 경로에서 각 3회 측정한 값이며 10–10,000 범위를 유지했다. MonPoly는 wrapper와 자식 프로세스의 VmHWM 합이며, 동시 RSS의 최고값과 동일한 통계는 아니다.', '',
              '| 힙 추적 고유 증명 수 | 활성 규칙 | 엔진 보유 힙 증가 MiB |', '|---:|---:|---:|']
    for r in heap:
        lines.append(f"| {r['n_proofs']} | {r['rules']} | {r['heap_growth_bytes']/2**20:.3f} |")
    lines += [f"| 100000 | 1 | {old100['heap_growth_kib']/1024:.3f} |", '',
              '힙 증가에는 위협 장부와 Gate의 중복 검사 사전 등이 함께 포함된다. 증명 하나의 상태 항목 자체 크기라는 뜻이 아니다. 힙 추적 프로세스의 RSS/HWM는 추적기 오버헤드가 있으므로 그림에 섞지 않는다. 진단 프로세스의 절대 RSS도 추가 import 때문에 스트리밍 판정기 그림값과 다르다.', '',
              'state.jsonl 30칸에서 상태 장부 항목 수는 고유 증명 수와 같았다. 규칙 1개와 21개 모두 thr015 namespace만 상태를 보유했고, Gate.seen의 항목 수는 접수 사건 수와 같았다. 초기화 직후 VmHWM가 현재 VmRSS보다 높고 작은 부하에서 최종 VmHWM가 그 초기 최대값을 넘지 않는 현상은 초기화 최대값이 성장을 가린다는 직접 근거다. 특정 컴파일러의 기여를 따로 분리한 측정은 아니다.', '',
              '## 기존 지연 검산과 비교 범위', '',
              '원본 사건 CSV 1,425,672행을 다시 묶어 240개 p95를 계산했고 저장 표와의 최대 차이는 0.00095ms였다(원자료 소수점 반올림). MonPoly의 1,500/2,000 runs/s 중앙값 역전은 반복 범위와 함께 기술해야 한다. 3,000 runs/s에서 판정기 없는 하네스도 지연이 증가하므로 그림의 지연 곡선은 2,000까지만 표시하고 원자료는 보존했다.', '',
              'PLTL과 MonPoly는 이 실험의 성공 조건과 누락 원자의 false 인코딩이 같아 곡선이 일치한다. 이는 입력 부족을 다루는 방식의 차이를 보여주며 선행 시스템 전체의 탐지 알고리즘 우위나 보편적인 비용 우위를 입증하지 않는다. 21규칙 측정도 모든 위협이 동시에 상태를 쌓는 혼합 부하나 제품 계측 비용의 측정은 아니다.', '']
    lines += ['## 메모리 진단표', '',
              '추가 모듈을 읽은 진단 프로세스의 값이며 본문 곡선에 합치지 않는다. 각 3회의 중앙값, MiB.', '',
              '| 증명 수 | 1규칙 초기 HWM | 1규칙 종료 RSS | 21규칙 초기 HWM | 21규칙 종료 RSS |', '|---:|---:|---:|---:|---:|']
    for n in (10, 1000, 10000, 31623, 100000):
        cells = []
        for count in (1, 21):
            rs = [r for r in state if r['rules'] == count and r['n_proofs'] == n]
            cells.extend(f"{st.median(r[k] for r in rs)/1024:.2f}" for k in ('hwm_after_init_kib', 'rss_end_kib'))
        lines.append(f"| {n} | " + ' | '.join(cells) + ' |')
    lines += ['## 본문 지연 곡선의 전체 반복 범위', '',
              '2026-10-21 원자료. 셀은 p95 반복 중앙값 [최소, 최대], ms.', '',
              '| 부하 runs/s | T-DID 1규칙 | PLTL | LTL3 | MonPoly | 하네스만 |', '|---:|---:|---:|---:|---:|---:|']
    for load in sorted(old_latency['tdid'], key=float):
        lines.append(f"| {float(load):g} | " + ' | '.join(format_range(old_latency[j][load]) for j in ('tdid', 'pltl', 'ltl3', 'fo', 'echo')) + ' |')
    lines += ['', '## 본문 메모리 곡선의 전체 반복 범위', '',
              '셀은 최대 상주 메모리 반복 중앙값 [최소, 최대], MiB.', '',
              '| 고유 증명 수 | T-DID 1규칙 | PLTL | LTL3 | MonPoly | 하네스만 |', '|---:|---:|---:|---:|---:|---:|']
    for n in sorted(memory, key=int):
        lines.append(f"| {n} | " + ' | '.join(format_range(fig3['memory_mib'][j][n], 2) for j in ('tdid', 'pltl', 'ltl3', 'fo', 'echo')) + ' |')
    lines += ['', '## 발송 경로 진단', '',
              'written_ms는 직렬화와 쓰기 시작 전 시각이다. 새 write_done_ms는 쓰기 반환 후 발송 스레드가 기록한 시각이며 수신 기록보다 늦을 수도 있어 순수 판정시간의 경계로 사용하지 않는다. 아래 구간은 예정→발송 시작과 발송 시작→최종 결과 수신이다. 후자는 직렬화·파이프·판정·수신 스케줄링을 함께 포함한다. 사건별 합은 전체 지연과 일치하지만 각 구간의 p95를 합하거나 다른 실행의 p95를 빼지 않는다.', '',
              '| 조건 | 부하 | 전체 p95 중앙값 ms | 발송 지각 p95 중앙값 ms | 발송 시작 이후 p95 중앙값 ms |', '|---|---:|---:|---:|---:|']
    for j, load in (('tdid', 2000), ('tdid_all', 2000), ('fo', 1500), ('fo_pre', 1500),
                    ('fo', 2000), ('fo_pre', 2000), ('echo', 3000), ('echo_pre', 3000)):
        rs = [r for r in timing if r['judge'] == j and r['load'] == load]
        lines.append(f"| {j} | {load} | " + ' | '.join(f"{st.median(r[k] for r in rs):.3f}" for k in ('total_ms', 'sender_late_ms', 'start_to_read_ms')) + ' |')
    lines += ['', '_pre는 동일 사건을 측정 창 전에 JSON으로 직렬화한 짝 비교이며 해당 진단은 각 3회다. 이 통제는 발송 중 JSON 직렬화의 기여를 확인하지만 운영체제 스케줄링·파이프 대기·모니터 내부 시간을 완전히 나누지는 못한다. 남은 변동을 특정 구성요소의 원인으로 단정하지 않는다. 주 그림의 원자료는 이 진단으로 교체하지 않았다.', '']
    (OUT / 'COST_FOLLOWUP_TABLES_20261022.md').write_text('\n'.join(lines) + '\n')
    mem10, mem10k = memory['10']['median'], memory['10000']['median']
    mem100 = st.median(r['rss_end_kib'] for r in state if r['rules'] == 1 and r['n_proofs'] == 100000)/1024
    p1, p21 = latency['tdid']['2000']['median'], latency['tdid_all']['2000']['median']
    mon15, mon20 = old_latency['fo']['1500.0'], old_latency['fo']['2000.0']
    manuscript = f'''# 제VI장 증거 누락과 처리 비용 수정본

## D Reliability under Missing Evidence

동일한 공통 이벤트와 위협 성공 조건을 사용하고 필수 정보의 일부를 제거한 뒤, 확정 오판과 보류 및 실제 공격에 대한 경보 여부를 비교했다. Fig. 3의 PLTL과 MonPoly는 모든 누락 비율에서 같은 값을 보였다. 이 실험에서는 두 비교군이 같은 원자 조건을 사용하고 누락된 값을 거짓으로 변환하기 때문이다. 따라서 두 곡선의 일치는 서로 다른 탐지 알고리즘의 성능 차이를 의미하지 않는다. 비교 결과는 고정한 성공 조건과 입력 인코딩 아래에서 정보 부족을 처리하는 방식의 영향을 보여준다.

T-DID의 확정 오판이 없다는 결과도 공격 미탐이 없다는 뜻은 아니다. 누락 비율이 0인 조건에서도 독립 정답이 확인된 공격 9건 중 6건을 탐지하고 3건을 보류했다. 보류를 경보 없음으로 계산하면 이 3건은 미탐에 포함된다. Fig. 3(c)의 정상 판정 또는 출력 없음에 따른 미탐과 보류를 합산해야 운영상 전체 미탐을 얻는다. 이 결과로 기존 모니터 전반의 탐지율 우위를 주장하지 않는다.

Fig. 3. 필수 정보의 누락에 따른 판정 변화. 39개 워크플로와 누락 확률별 30개 시드를 사용했다. (a)는 전체 워크플로의 확정 오판, (b)는 보류, (c)는 실제 공격 9건에서 정상 판정 또는 출력 없음으로 경보가 나지 않은 비율과 공격으로 판정한 비율이다. (c)의 나머지는 보류이며 운영상 미탐에 포함된다. PLTL과 MonPoly는 이 입력 인코딩에서 값이 같아 범례를 통합했다. 곡선은 시드 평균이고 반복 범위는 보충표에 제시한다.

## E Runtime Cost

Fig. 4는 동일한 합성 THR-015 사건 열을 별도 스트리밍 판정기에 재생했을 때의 메모리와 지연을 보여준다. 기본 비교에서는 T-DID도 비교군과 동일한 과제인 THR-015 규칙 하나만 활성화했다. 지연에는 판정뿐 아니라 JSON 처리와 프로세스 간 전달 및 하네스 스케줄링이 포함된다. 제품에 수집 지점을 추가하는 비용이나 발급 서비스 전체의 응답시간을 측정한 값은 아니다.

고유 증명 10개와 10,000개에서 T-DID의 최대 상주 메모리 중앙값은 각각 {mem10:.1f}MiB와 {mem10k:.1f}MiB였다. 별도 진단에서는 위협 장부 항목 수가 고유 증명 수와 같았으며 중복 검사 사전도 접수 사건 수에 따라 증가했다. 100,000개에서 진단 프로세스의 종료 RSS는 중앙값 {mem100:.1f}MiB였고, 힙 추적에서 엔진 보유 힙은 약 {old100['heap_growth_kib']/1024:.1f}MiB 증가했다. 작은 범위에서 최대 메모리가 거의 일정했던 것은 초기화 과정의 최대값 아래에서 상태 증가가 가려졌기 때문이다. 힙 증가에는 위협 장부와 입력 접수 장부가 함께 포함된다. 진단 프로세스와 힙 추적기의 절대 RSS를 본문의 스트리밍 메모리 곡선에 합치지 않았으며, 이 구현의 상태 공간이 일정하다고 해석하지 않는다.

추가로 모든 규칙 21개를 활성화하고 같은 발급 부하에서 5회씩 측정했다. 2,000 runs/s에서 p95의 반복 중앙값은 규칙 하나일 때 {p1:.3f}ms, 전체 규칙을 켰을 때 {p21:.3f}ms였다. 이 사건 종류에 반응하는 규칙은 6개이고 상태를 축적한 규칙은 THR-015뿐이다. 따라서 이 결과는 전체 규칙이 로딩된 상태의 해당 발급 부하를 설명하며 모든 위협이 동시에 발생하는 경우의 처리 비용을 나타내지 않는다. 반복 최솟값과 최댓값 및 다른 부하의 결과는 보충표에 제시한다.

실제 처리 경로의 입력 검사와 규칙 평가 및 상태 저장도 따로 계측했다. 입력 검사는 프로필과 스키마 및 불변식 확인, 내용 지문과 중복 및 순서 관리를 포함한다. 규칙 평가는 상태 조회를 포함하고 상태 저장은 commit을 별도로 측정했다. 타이머를 넣은 경로와 넣지 않은 경로의 THR-015 판정이 같음을 확인했으며, 분해 결과는 타이머 비용을 포함한 진단값으로 제시한다. 이 분해를 스키마 검사만의 비용이나 배포 환경의 지연으로 해석하지 않는다.

기존 반복 측정에서 MonPoly의 1,500과 2,000 runs/s p95 중앙값은 각각 {mon15['median']:.3f}ms와 {mon20['median']:.3f}ms였고, 반복 범위는 각각 {mon15['min']:.3f}–{mon15['max']:.3f}ms와 {mon20['min']:.3f}–{mon20['max']:.3f}ms로 넓었다. 또한 3,000 runs/s에서는 판정기 없는 하네스도 p95 중앙값이 약 266ms로 증가했다. Fig. 4의 지연 곡선은 이 영향을 피해 2,000 runs/s까지만 표시했다. 이 결과는 측정한 구현 경로의 비용을 보여주며, T-DID의 보편적인 지연 또는 메모리 우위를 입증하지 않는다.

발송 경로를 확인하기 위해 같은 사건의 JSON 직렬화를 측정 창 전에 수행하는 조건도 각 3회 짝 비교했다. 판정기 없는 3,000 runs/s의 p95 중앙값은 {latency['echo']['3000']['median']:.3f}ms에서 {latency['echo_pre']['3000']['median']:.3f}ms로, MonPoly의 2,000 runs/s 값은 {latency['fo']['2000']['median']:.3f}ms에서 {latency['fo_pre']['2000']['median']:.3f}ms로 낮아졌다. 이는 발송 중 직렬화가 측정 경로에 영향을 준다는 근거이며 순수 엔진 시간의 추정치는 아니다. 운영체제 스케줄링과 파이프 대기 및 모니터 내부 처리의 기여를 완전히 분리하지는 못했으므로, 남은 변동의 원인을 특정하지 않는다. 이 진단값으로 본 곡선을 일부만 교체하지 않았다.

Fig. 4. 동일한 합성 THR-015 부하에 대한 판정 처리 비용. (a)는 고유 증명 수 10–10,000에 대한 최대 상주 메모리, (b)는 제공 부하에 대한 p95 지연이다. 각 표지는 메모리 3회와 지연 5회의 중앙값이며, 범위는 보충표에 제시한다. 초기 최대값이 상태 증가를 가리는 현상을 확인한 100,000개 진단은 별도 보충표에 제시한다. MonPoly 메모리는 wrapper와 자식 프로세스의 VmHWM 합이다. T-DID 본 곡선은 THR-015 규칙 하나를 활성화한 조건이며, 21규칙 조건은 보충표에서 구분한다. 3,000 runs/s는 판정기 없는 하네스도 대기열이 증가해 지연 그림에서 제외했으며 원자료는 보존했다.
'''
    (ROOT / 'docs/paper/evaluation-rq3-rq4-corrected-20261022.md').write_text(manuscript)


if __name__ == '__main__':
    main()
