"""Regression: Contact dependency alone is not a usable-password witness.

All inputs are freshly generated synthetic state machines. No real avatar,
password, author identity, or runtime configuration is read by this test.
"""
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path


def cond(parameter, mode, threshold=0):
    return dict(parameter=parameter, mode=mode, threshold=threshold)


def edge(destination, *conditions, timed=False):
    return dict(destination=destination, conditions=list(conditions),
                has_exit_time=timed, exit_time=.05 if timed else 0,
                duration=0, has_fixed_duration=True)


def write(name, value):
    return dict(name=name, type=0, value=value)


def fixture(seed, depth='fast', with_contact=True):
    rng = random.Random(seed)
    names = ['p' + str(rng.getrandbits(48)) for _ in range(5)]
    key, reset, sense, latch, restore = names
    digits = [rng.randrange(10) for _ in range(rng.randrange(4, 9))]
    raw = list(range(1, 11))
    rng.shuffle(raw)
    states = []
    terminal, failed = len(digits) * 2, len(digits) * 2 + 1
    for i, digit in enumerate(digits):
        expected = raw[digit]
        states.append(dict(name='press-' + str(i), transitions=[
            edge(i * 2 + 1, cond(key, 6, expected), cond(reset, 2)),
            edge(failed, cond(key, 7, 0), cond(key, 7, expected), cond(reset, 2))]))
        states.append(dict(name='release-' + str(i), transitions=[
            edge(i * 2 + 2, cond(key, 6, 0), cond(reset, 2))]))
    states += [dict(name='terminal', transitions=[], parameter_writes=[
        write(latch, 0), write(restore, 1)]),
        dict(name='failure', transitions=[edge(0, cond(key, 6, 0))],
             parameter_writes=[write(latch, 1), write(restore, 0)])]
    producer = dict(default_state=0, default_weight=1, any_transitions=[], states=[
        dict(name='boot', transitions=[edge(1, cond('AvatarVersion', 6, 3))]),
        dict(name='on-wait', transitions=[edge(4, timed=True)]),
        dict(name='retry', parameter_writes=[write(reset, 1)], transitions=[edge(1, timed=True)]),
        dict(name='ready', parameter_writes=[write(reset, 0)], transitions=[]),
        dict(name='check-high', transitions=[edge(5, cond(sense, 3, .5)), edge(2, cond(sense, 4, .5))]),
        dict(name='off-wait', transitions=[edge(6, timed=True)]),
        dict(name='check-low', transitions=[edge(3, cond(sense, 4, .5)), edge(2, cond(sense, 3, .5))]),
    ])
    machines = [producer, dict(default_state=0, default_weight=1,
                              states=states, any_transitions=[])]
    for i in range(3):
        machines.append(dict(default_state=0, default_weight=1, any_transitions=[],
                             states=[dict(name='consumer-' + str(i),
                                          transitions=[edge(0, cond(latch, 1))])]))
    defaults = [dict(name=key, type='int', default=0),
                dict(name=reset, type='bool', default=with_contact),
                dict(name=sense, type='float', default=1),
                dict(name=latch, type='bool', default=True),
                dict(name=restore, type='float', default=0),
                dict(name='AvatarVersion', type='int', default=0)]
    if not with_contact:
        # Negative control: there is no external prerequisite; the gate
        # becomes ready through a wholly deterministic producer instead.
        machines[0] = dict(default_state=0, default_weight=1, any_transitions=[],
                           states=[dict(name='ready', transitions=[],
                                        parameter_writes=[write(reset, 0)])])
    graph = dict(schema=1, graph_schema_version='vpf-structural-graph/1',
                 source_sha256='a' * 64, analysis_depth=depth,
                 deep_scan_machine_count=len(machines) if depth != 'fast' else 0,
                 stats=dict(controller_ok=1, controller_fail=0),
                 active_fx_controller_ids=['1'], active_root_menu_ids=['1'],
                 controllers=[dict(path_id='1', name='synthetic', parameters=[x['name'] for x in defaults],
                                   parameter_defaults=defaults, machines=machines)],
                 expression_parameters=[dict(name=key, value_type=0, default=0, saved=False),
                                        dict(name=latch, value_type=2, default=1, saved=True)],
                 menus=[dict(id='1', name='root', controls=[dict(name='密码锁', type=103, submenu='2')]),
                        dict(id='2', name='keypad', controls=[dict(name=str(i), type=101, parameter=key,
                                                               value=raw[i]) for i in range(10)])],
                 contact_components=[])
    if with_contact:
        shared = dict(enabled=True, game_object_active=True, position=[0, 0, 0],
                      local_position=[0, 0, 0], tags=['synthetic-tag'])
        graph['contact_components'] = [dict(shared, kind='receiver', path_id='11',
              parameter=sense, allow_self=True, receiver_type=0, transform='101',
              parent_transform='100', hierarchy_path_hashes=[101]),
              dict(shared, kind='sender', path_id='12', transform='102',
                   parent_transform='101', hierarchy_path_hashes=[102])]
        # Deliberately unresolved activation binding: matches neither sender
        # nor receiver. Both polarities do NOT prove a physical pulse.
        if depth != 'fast':
            for i, state in enumerate(machines[0]['states']):
                state['animation_constant_writes'] = [dict(name='m_Enabled',
                    attribute_hash=3305885265, path_hash=999, type_id=114,
                    custom_type=24, value=0 if i in (3, 5, 6) else 1)]
    return graph, ''.join(map(str, digits))


def run(worker, graph):
    with tempfile.TemporaryDirectory(prefix='contact-confidence-') as tmp:
        path = Path(tmp) / 'fixture.json'
        path.write_text(json.dumps(graph), encoding='utf-8')
        proc = subprocess.run([worker, 'analyze-graph', str(path.resolve()), '--json'],
                              capture_output=True, text=True, encoding='utf-8', timeout=30)
        if proc.returncode:
            raise AssertionError('worker failed: ' + proc.stderr[:200])
        return json.loads(proc.stdout)


def main():
    worker = sys.argv[1]
    counts = dict(guarded=0, deterministic_control=0,
                  polarity_only=0, complete_receiver_witness=0)
    for seed in range(12):
        for depth in ('fast', 'targeted_deep'):
            graph, expected = fixture(seed, depth)
            report = run(worker, graph)
            matches = [x for x in report['password_candidates'] if x['password'] == expected]
            assert matches, 'synthetic digit path unexpectedly lost'
            assert all(x['confidence'] != '高' and x['runtime_status'] == 'runtime_incomplete'
                       for x in matches), 'Contact presence incorrectly certifies a password'
            assert not any(x['password'] == expected for x in report['results']), 'unready password promoted'
            assert not any(x['password'] == expected for x in report['guides']), 'unready guide emitted'
            counts['guarded'] += 1
        graph, expected = fixture(seed, 'targeted_deep', with_contact=False)
        report = run(worker, graph)
        assert any(x['password'] == expected for x in report['results']), 'deterministic control regressed'
        counts['deterministic_control'] += 1
        graph, expected = fixture(seed, 'targeted_deep')
        for state in graph['controllers'][0]['machines'][0]['states']:
            for activation in state['animation_constant_writes']:
                activation['path_hash'] = 102
        report = run(worker, graph)
        assert not any(x['password'] == expected for x in report['results']), 'polarity presence promoted without a pulse witness'
        counts['polarity_only'] += 1
        graph, expected = fixture(seed, 'targeted_deep')
        graph['contact_components'] = graph['contact_components'][:1]
        for state in graph['controllers'][0]['machines'][0]['states']:
            state.pop('animation_constant_writes', None)
        report = run(worker, graph)
        assert any(x['password'] == expected for x in report['results']), 'complete hidden receiver witness regressed'
        counts['complete_receiver_witness'] += 1
    print('CONTACT_CONFIDENCE_OK|' + '|'.join(str(k) + '=' + str(v) for k, v in counts.items()))


if __name__ == '__main__':
    main()
