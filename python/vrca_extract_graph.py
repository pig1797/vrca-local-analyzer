# -*- coding: utf-8 -*-
"""Data-only Unity snapshot adapter for VrcNativeCore.

This module intentionally contains no password, lock-classification, menu
mapping, unlock, or verification decisions.  It only converts Unity objects
to a stable JSON schema consumed by the local C++ core.
"""
import json
import hashlib
import math
import os
import re
import struct
import sys
import time
import zlib
import copy
from collections import Counter

# Embedded Python distributions may omit the script directory from sys.path.
# Always use the sibling guard shipped with this local candidate.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vrca_memory_guard import apply_windows_memory_limit

apply_windows_memory_limit()

try:
    import UnityPy
except ImportError:
    print("ERR|UnityPy 未安装")
    raise SystemExit(2)

# Disable the optional native TypeTree reader before UnityPy.load().  Bundle
# construction may parse container metadata immediately, so disabling it only
# inside read_typetree_safe() is too late for malformed third-party TypeTrees:
# the native extension can access-violate before Python gets an exception to
# handle.  The bounds-checked Python reader is slower but fail-safe and the
# adapter only visits the small set of controller/menu objects it needs.
try:
    import UnityPy.helpers.TypeTreeHelper as _TypeTreeHelper
    _TypeTreeHelper.read_typetree_boost = None
except Exception:
    pass

def _assetbundle_metadata_readable(obj, node=None):
    """Validate only this optional metadata object's bytes, not its neighbors."""
    from UnityPy.helpers import TypeTreeHelper as helper
    from UnityPy.streams import EndianBinaryReader

    # Match read_typetree_safe's bounded reader and original alignment. Unlike
    # that best-effort helper, let resource/IO failures reach the caller.
    source_reader = obj.reader
    position = source_reader.Position
    try:
        data = bytes(obj.get_raw_data())
    finally:
        source_reader.Position = position
    phase = int(obj.byte_start) % 4
    reader = EndianBinaryReader(bytes(phase) + data if phase else data,
                               endian=getattr(source_reader, "endian", "<"))
    reader.Position = phase
    saved = getattr(helper, "read_typetree_boost", None)
    helper.read_typetree_boost = None
    try:
        tree = helper.read_typetree(
            obj._get_typetree_node(node), reader, as_dict=True,
            assetsfile=obj.assets_file, byte_size=len(data), check_read=True)
        return tree is not None
    finally:
        helper.read_typetree_boost = saved


def _install_assetbundle_metadata_compat(reader_class, container_class):
    """Cover UnityPy 1.23 read() and 1.25 parse_as_object(), idempotently."""
    def original_method(method, legacy_name, legacy_global):
        # A second import must not stack wrappers or retain the old broad
        # parse_as_object exception handler from an earlier adapter import.
        if getattr(method, "__name__", "") == legacy_name:
            scope = getattr(method, "__globals__", {})
            previous = scope.get(legacy_global)
            if scope.get("_ObjectReader") is reader_class and callable(previous) and previous is not method:
                return previous
        return method

    def guarded_entry(original, entry):
        def read_metadata(self, *args, **kwargs):
            # ClassID 142 is AssetBundle container metadata, not a controller,
            # animation, menu, or another object used as analysis evidence.
            if self.type != 142:
                return original(self, *args, **kwargs)
            node = (args[0] if args else kwargs.get("node")) if entry == "parse_as_object" else None
            try:
                if not _assetbundle_metadata_readable(self, node):
                    return None
                # Preserve the library's ordinary wrapped-object result and
                # argument semantics after the bounded preflight succeeds.
                return original(self, *args, **kwargs)
            except (MemoryError, OSError):
                raise
            except Exception:
                # Only unreadable optional container metadata may be absent.
                # The serialized objects and their later checks remain intact.
                return None
        read_metadata._vrca_assetbundle_compat = 1
        read_metadata._vrca_assetbundle_original = original
        return read_metadata

    for entry in ("read", "parse_as_object"):
        method = getattr(reader_class, entry, None)
        if not callable(method) or getattr(method, "_vrca_assetbundle_compat", None) == 1:
            continue
        method = original_method(method, "_safe_parse_as_object", "_original_parse_as_object")
        setattr(reader_class, entry, guarded_entry(method, entry))

    initializer = container_class.__init__
    if getattr(initializer, "_vrca_assetbundle_compat", None) != 1:
        initializer = original_method(initializer, "_safe_container_init", "_original_container_init")

        def init_container(self, container, *args, **kwargs):
            if container is None:
                # Let each UnityPy version establish all of its own empty
                # container invariants (including container_dict in 1.25).
                return initializer(self, [], *args, **kwargs)
            return initializer(self, container, *args, **kwargs)
        init_container._vrca_assetbundle_compat = 1
        init_container._vrca_assetbundle_original = initializer
        container_class.__init__ = init_container


# Install before UnityPy.load() constructs SerializedFile containers. Import
# errors must not silently leave the expected compatibility protection absent.
from UnityPy.files.ObjectReader import ObjectReader as _ObjectReader
from UnityPy.helpers import ContainerHelper as _ContainerHelper
_install_assetbundle_metadata_compat(_ObjectReader, _ContainerHelper.ContainerHelper)


def unwrap(value):
    while isinstance(value, dict) and len(value) == 1 and "data" in value:
        value = value["data"]
    return value


def fix(value):
    value = str(value or "")
    try:
        return value.encode("latin-1").decode("utf-8")
    except Exception:
        return value


_ref_cache = {}


def read_typetree_safe(obj, nodes=None):
    """Read within this object only, without entering UnityPyBoost native code."""
    try:
        import UnityPy.helpers.TypeTreeHelper as helper
        saved = getattr(helper, "read_typetree_boost", None)
        helper.read_typetree_boost = None
        try:
            if callable(getattr(obj, "_get_typetree_node", None)) and callable(getattr(obj, "get_raw_data", None)):
                from UnityPy.streams import EndianBinaryReader
                data = bytes(obj.get_raw_data())
                # UnityPy's ObjectReader otherwise traverses the entire shared
                # serialized-file buffer and checks byte_size only afterwards.
                # A malformed count can walk adjacent objects for minutes.
                # Preserve the original modulo-4 alignment even on old files.
                phase = int(getattr(obj, "byte_start", 0) or 0) % 4
                reader = EndianBinaryReader(bytes(phase) + data if phase else data,
                    endian=getattr(obj.reader, "endian", "<"))
                reader.Position = phase
                return helper.read_typetree(obj._get_typetree_node(nodes), reader,
                    as_dict=True, assetsfile=getattr(obj, "assets_file", None),
                    byte_size=len(data), check_read=True)
            if nodes is None:
                return obj.read_typetree()
            return obj.read_typetree(nodes=nodes)
        finally:
            helper.read_typetree_boost = saved
    except Exception:
        return None


def reference_node(unity_version, class_id=91):
    key = (unity_version, class_id)
    if key in _ref_cache:
        return _ref_cache[key]
    node = None
    try:
        from UnityPy.helpers import Tpk
        from UnityPy.helpers.UnityVersion import UnityVersion
        node = Tpk.get_typetree_node(class_id, UnityVersion.from_str(unity_version))
    except Exception:
        pass
    _ref_cache[key] = node
    return node


def read_typetree_bytes(obj, node, data):
    try:
        import UnityPy.helpers.TypeTreeHelper as helper
        from UnityPy.streams import EndianBinaryReader
        endian = ">" if getattr(obj.reader, "endian", "<") == ">" else "<"
        saved = getattr(helper, "read_typetree_boost", None)
        helper.read_typetree_boost = None
        try:
            return helper.read_typetree(
                node,
                EndianBinaryReader(data, endian),
                as_dict=True,
                assetsfile=obj.assets_file,
                byte_size=len(data),
                check_read=False,
            )
        finally:
            helper.read_typetree_boost = saved
    except Exception:
        return None


def read_controller(obj):
    try:
        version = obj.assets_file.unity_version
    except Exception:
        version = None
    ref = reference_node(version, 91) if version else None
    try:
        raw = obj.get_raw_data()
        endian = ">" if getattr(obj.reader, "endian", "<") == ">" else "<"
        name_length = struct.unpack_from(endian + "I", raw, 0)[0]
    except Exception:
        raw = b""
        name_length = 0
    # Protected bundles seen in the field prepend one to four junk bytes to
    # selected AnimatorControllers.  Calling the normal reader on the bogus
    # multi-megabyte string length can spend seconds walking invalid data.
    # Validate the leading serialized name first, then repair only the
    # measured prefix shift.
    if raw and not (0 < name_length <= min(1024, len(raw) - 4)):
        for count in range(1, 5):
            if count + 4 > len(raw):
                break
            shifted_length = struct.unpack_from(endian + "I", raw, count)[0]
            if not (0 < shifted_length <= min(1024, len(raw) - count - 4)):
                continue
            repaired = raw[count:] + bytes(count)
            tree = read_typetree_bytes(obj, ref or obj._get_typetree_node(None), repaired)
            if isinstance(tree, dict):
                return tree
        return None
    if ref is not None:
        return read_typetree_safe(obj, nodes=ref)
    return read_typetree_safe(obj)


def script_name_map(environment):
    result = {}
    for obj in environment.objects:
        if obj.type.name != "MonoScript":
            continue
        tree = read_typetree_safe(obj)
        if not isinstance(tree, dict):
            # Some bundles prefix MonoScript payloads with 1-4 zero bytes.
            # Only accept a unique complete metadata-shaped interpretation;
            # never guess the script class from a raw keyword substring.
            candidates = []
            try:
                raw = obj.get_raw_data()
                node = obj._get_typetree_node(None)
                for shift in range(1, 5):
                    if raw[:shift] != bytes(shift):
                        continue
                    try:
                        parsed = read_typetree_bytes(obj, node, raw[shift:] + bytes(shift))
                    except Exception:
                        continue
                    if not isinstance(parsed, dict):
                        continue
                    cls = parsed.get("m_ClassName")
                    assembly = parsed.get("m_AssemblyName")
                    namespace = parsed.get("m_Namespace", "")
                    # Padding can replace a truncated assembly tail. Only the
                    # fully present repeated class identity is used; never
                    # load or reconstruct an assembly from this metadata.
                    assembly = assembly.rstrip("\0") if isinstance(assembly, str) else assembly
                    if (isinstance(cls, str) and cls and cls.isidentifier() and
                            parsed.get("m_Name") == cls and isinstance(assembly, str) and
                            assembly and len(assembly) < 256 and not any(ord(c) < 32 for c in assembly) and
                            isinstance(namespace, str) and all(part.isidentifier() for part in namespace.split('.') if part)):
                        candidates.append(parsed)
            except Exception:
                pass
            if len(candidates) != 1:
                continue
            tree = candidates[0]
        name = fix(tree.get("m_ClassName") or tree.get("m_Name", ""))
        if name:
            result[int(obj.path_id)] = name
    return result


def mono_script_location(obj, scripts):
    try:
        data = obj.get_raw_data()
        if len(data) < 28:
            return "", 0
        endian = ">" if getattr(obj.reader, "endian", "<") == ">" else "<"
        matches = []
        for shift in range(5):
            offset = 20 + shift
            if offset + 8 > len(data):
                continue
            path_id = struct.unpack_from(endian + "q", data, offset)[0]
            name = scripts.get(path_id, "")
            if name:
                matches.append((name, shift))
        return matches[0] if len(matches) == 1 else ("", 0)
    except Exception:
        return "", 0


def mono_script_name(obj, scripts):
    return mono_script_location(obj, scripts)[0]


def _pointer_path_id(value):
    value = unwrap(value)
    if not isinstance(value, dict):
        return 0
    try:
        return int(value.get("m_PathID", value.get("path_id", 0)) or 0)
    except Exception:
        return 0


def _vrc_mono_score(tree, scripts):
    """Score only VRChat menu/parameter shapes; no lock decision is made."""
    if not isinstance(tree, dict):
        return -1
    script_name = scripts.get(_pointer_path_id(tree.get("m_Script")), "")
    if script_name not in ("VRCExpressionsMenu", "VRCExpressionParameters"):
        return -1
    score = 100
    name = fix(tree.get("m_Name", ""))
    if name:
        score += 10
    controls = tree.get("controls")
    parameters = tree.get("parameters")
    if script_name == "VRCExpressionsMenu":
        if not isinstance(controls, list) or not (1 <= len(controls) <= 8):
            return -1
        score += 30
        for control in controls:
            if not isinstance(control, dict):
                return -1
            if isinstance(control.get("name"), str):
                score += 2
            if isinstance(control.get("subMenu"), dict):
                score += 2
            try:
                int(control.get("type", 0) or 0)
                score += 1
            except Exception:
                return -1
    else:
        # Large production avatars can legitimately exceed 512 expression
        # parameters after VRCFury/Modular Avatar expansion.  Rejecting the
        # complete asset here silently removed every menu-facing lock input
        # from the normalized graph.  Keep a defensive ceiling, but size it
        # above VRChat build-time generated tables.
        if not isinstance(parameters, list) or len(parameters) > 4096:
            return -1
        score += 25
        if all(isinstance(parameter, dict) for parameter in parameters):
            score += min(len(parameters), 16)
    return score


def read_vrc_mono_safe(obj, scripts):
    """Read a VRChat MonoBehaviour, repairing bounded header-byte shifts.

    A few protected bundles insert one to four junk bytes between the
    GameObject and MonoBehaviour header fields.  The object length is kept
    unchanged while candidate shifts are parsed with the pure-Python reader.
    Only candidates whose script reference and schema both validate are
    returned.
    """
    try:
        raw = obj.get_raw_data()
        endian = ">" if getattr(obj.reader, "endian", "<") == ">" else "<"
    except Exception:
        return None, False

    target_ids = [
        path_id for path_id, name in scripts.items()
        if name in ("VRCExpressionsMenu", "VRCExpressionParameters")
    ]
    target_positions = []
    for path_id in target_ids:
        marker = struct.pack(endian + "q", int(path_id))
        position = raw.find(marker, 12, min(len(raw), 48))
        if position >= 0:
            target_positions.append(position)
    if not target_positions:
        return None, False

    # A normal MonoBehaviour stores the script path ID at byte 20.  Avoid
    # running dozens of speculative parses when that unshifted layout works.
    if 20 in target_positions:
        normal = read_typetree_safe(obj)
        if _vrc_mono_score(normal, scripts) >= 0:
            return normal, False

    try:
        import UnityPy.helpers.TypeTreeHelper as helper
        from UnityPy.streams import EndianBinaryReader
        node = obj._get_typetree_node(None)
    except Exception:
        return None, False

    # The distance from the expected script pointer directly tells us how
    # many junk bytes were inserted.  This keeps recovery bounded to at most
    # nine pure-Python parses instead of the old 36-way brute-force loop.
    shift_counts = sorted({
        position - 20 for position in target_positions
        if 1 <= position - 20 <= 4
    })
    if not shift_counts:
        return None, False
    saved = getattr(helper, "read_typetree_boost", None)
    helper.read_typetree_boost = None
    try:
        for count in shift_counts:
            for start in range(12, 21):
                if start + count > len(raw):
                    continue
                repaired = raw[:start] + raw[start + count:] + bytes(count)
                try:
                    tree = helper.read_typetree(
                        node,
                        EndianBinaryReader(repaired, endian),
                        as_dict=True,
                        assetsfile=obj.assets_file,
                        byte_size=len(repaired),
                        check_read=False,
                    )
                except Exception:
                    continue
                score = _vrc_mono_score(tree, scripts)
                if score >= 0:
                    return tree, True
    finally:
        helper.read_typetree_boost = saved
    return None, False


def parameter_name(condition, tos):
    event_id = condition.get("m_EventID")
    return fix(tos.get(event_id, event_id))


def unity_animator_string_to_hash(name):
    """Return Unity Animator.StringToHash's stable CRC32 identifier.

    Unity documents Animator.StringToHash as CRC32.  The serialized
    AnimatorController stores parameter/event IDs as the reflected CRC32 of
    the UTF-8 parameter name (standard reflected polynomial, init/final
    xor 0xffffffff).  Keeping this in the data adapter lets us recover names
    that are omitted from m_TOS by generated VRCFury controllers.
    """
    raw = fix(name).encode("utf-8")
    return zlib.crc32(raw) & 0xFFFFFFFF


def _menu_parameter_names(menus):
    """Collect parameter names from all menu controls, including nested ones."""
    names = set()

    def visit(control):
        if not isinstance(control, dict):
            return
        parameter = fix(control.get("parameter", ""))
        if parameter:
            names.add(parameter)
        for parameter in control.get("sub_parameters", []) or []:
            parameter = fix(parameter)
            if parameter:
                names.add(parameter)
        submenu = (control.get("sub_menu") or control.get("subMenu") or
                   control.get("submenu"))
        if isinstance(submenu, dict):
            for child in submenu.get("controls", []) or []:
                visit(child)

    for menu in menus or []:
        if not isinstance(menu, dict):
            continue
        for control in menu.get("controls", []) or []:
            visit(control)
    return names


def transition_json(raw, tos, state_index_by_id=None, state_count=None, selector_count=0):
    transition = unwrap(raw)
    if not isinstance(transition, dict):
        return None
    raw_destination = _strict_int(transition.get("m_DestinationState", -1))
    destination = -1
    if raw_destination is not None:
        if isinstance(state_index_by_id, dict) and raw_destination in state_index_by_id:
            destination = state_index_by_id[raw_destination]
        elif selector_count and raw_destination >= 30000:
            # A selector reference is not a state-array index. Preserve it for
            # ordered dispatch evaluation; legacy state-only proofs fail closed.
            destination = -1
        elif (state_count is not None and raw_destination >= 30000 and
                0 <= raw_destination - 30000 < state_count):
            # Unity AnimatorController constants commonly encode local state
            # references as 30000 + state-array-index.  Generated ModularAvatar
            # toggle/keypad layers use this form heavily; without this mapping
            # every edge becomes -1 and the analyzer misses the lock entirely.
            destination = raw_destination - 30000
        elif state_count is not None and 0 <= raw_destination < state_count:
            # Older snapshots accidentally treated this serialized value as an
            # array index.  Keep the fallback for controllers that really store
            # an index, but prefer the FullPathID map above.
            destination = raw_destination
    result = {
        "destination": destination,
        "raw_destination": raw_destination,
        "conditions": [],
        "has_exit_time": bool(transition.get("m_HasExitTime", False)),
        "exit_time": float(transition.get("m_ExitTime", 0.0) or 0.0),
        "duration": float(transition.get("m_TransitionDuration", 0.0) or 0.0),
        # Preserve runtime ordering/interruption semantics.  The native core
        # may not model every mode yet, but losing these fields here made a
        # transition look deterministic when Unity could interrupt it.
        "has_fixed_duration": bool(transition.get("m_HasFixedDuration", False)),
        "interruption_source": int(transition.get("m_InterruptionSource", 0) or 0),
        "ordered_interruption": bool(transition.get("m_OrderedInterruption", False)),
        "can_transition_to_self": bool(transition.get("m_CanTransitionToSelf", False)),
    }
    if (raw_destination is not None and selector_count and
            30000 <= raw_destination < 30000 + selector_count and
            raw_destination not in (state_index_by_id or {})):
        result["selector_destination"] = raw_destination - 30000
    raw_conditions = transition.get("m_ConditionConstantArray", []) or []
    result["raw_condition_count"] = len(raw_conditions)
    for raw_index, raw_condition in enumerate(raw_conditions):
        condition = unwrap(raw_condition)
        if not isinstance(condition, dict):
            continue
        invalid_threshold = False
        try:
            threshold = float(condition.get("m_EventThreshold", 0))
        except Exception:
            threshold = 0.0
            invalid_threshold = True
        try:
            condition_exit = float(condition.get("m_ExitTime", 0.0))
        except (TypeError, ValueError, OverflowError):
            condition_exit = float("nan")
        row = {
            "mode": int(condition.get("m_ConditionMode", 0) or 0),
            "parameter": parameter_name(condition, tos),
            "parameter_hash": _strict_int(condition.get("m_EventID")),
            "raw_index": raw_index,
            "threshold": threshold if math.isfinite(threshold) else None,
            "exit_time": condition_exit if math.isfinite(condition_exit) else None,
        }
        if invalid_threshold:
            row["threshold_encoding"] = "invalid"
        elif not math.isfinite(threshold):
            row["threshold_encoding"] = "nan" if math.isnan(threshold) else "positive_infinity" if threshold > 0 else "negative_infinity"
        result["conditions"].append(row)
    return result


def _selector_states_json(machine, tos, state_count):
    raw = machine.get("m_SelectorStateConstantArray", []) or []
    result = []
    for index, item in enumerate(raw):
        selector = unwrap(item)
        if not isinstance(selector, dict):
            raise ValueError("selector_layout_incomplete")
        transitions = []
        for edge in selector.get("m_TransitionConstantArray", []) or []:
            edge = unwrap(edge)
            if not isinstance(edge, dict):
                raise ValueError("selector_transition_incomplete")
            mapped = dict(edge, m_DestinationState=edge.get("m_Destination"))
            transitions.append(transition_json(mapped, tos, {}, state_count, len(raw)))
        result.append({"index": index, "is_entry": selector.get("m_IsEntry") is True,
                       "transitions": transitions})
    return result


def _animation_clip_stable_material_pointer(tree):
    """A deliberately narrow data-only witness, never a restore authorization."""
    bc = unwrap(tree.get("m_ClipBindingConstant", {}))
    clip = unwrap(unwrap(tree.get("m_MuscleClip", {})).get("m_Clip", {}))
    bindings = bc.get("genericBindings", []) or []
    mapping = bc.get("pptrCurveMapping", []) or []
    if len(bindings) != 1 or not mapping or len(mapping) > 256:
        return []
    b = unwrap(bindings[0])
    if (b.get("typeID") not in (23, 137) or b.get("customType") != 21 or
            b.get("isPPtrCurve") != 1 or b.get("isIntCurve", 0) or
            b.get("isSerializeReferenceCurve", 0)):
        return []
    pointers = {_local_pptr(p) for p in mapping}
    if len(pointers) != 1 or None in pointers or 0 in pointers:
        return []
    streamed = unwrap(clip.get("m_StreamedClip", {}))
    if (streamed.get("curveCount") != 0 or streamed.get("discreteCurveCount") != 1 or
            unwrap(clip.get("m_DenseClip", {})).get("m_CurveCount") != 0 or
            unwrap(clip.get("m_ConstantClip", {}))):
        return []
    words = streamed.get("data", [])
    if not isinstance(words, list) or not 2 <= len(words) <= 10000:
        return []
    if any(_strict_int(w) is None or not 0 <= w <= 0xffffffff for w in words):
        return []
    pos, samples, terminal = 0, 0, False
    previous = -float("inf")
    while pos + 2 <= len(words):
        time, count = _float_from_u32_bits(words[pos]), words[pos + 1]
        pos += 2
        if time is None or math.isnan(time) or time < previous:
            return []
        previous = time
        if math.isinf(time):
            terminal = time > 0 and count == 0 and pos == len(words)
            break
        if count != 1 or pos + 5 > len(words) or words[pos] != 0:
            return []
        coeff = [_float_from_u32_bits(w) for w in words[pos + 1:pos + 5]]
        pos += 5
        if (any(v is None or not math.isfinite(v) for v in coeff) or
                any(v != 0 for v in coeff[:3]) or
                coeff[3] != int(coeff[3]) or not 0 <= coeff[3] < len(mapping)):
            return []
        samples += 1
    if not terminal or not samples:
        return []
    return [{"path_hash": b["path"], "attribute_hash": b["attribute"],
             "type_id": b["typeID"], "custom_type": 21,
             "material_path_id": str(next(iter(pointers))),
             "source": "stable_material_pptr", "runtime_verified": False}]


def state_name(state, index, tos):
    name_id = state.get("m_NameID") or state.get("m_FullPathID")
    return fix(tos.get(name_id, "st%d" % index))


def _strict_int(value):
    """Return an exact integer, or None for an ambiguous serialized value."""
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    try:
        if isinstance(value, float) and value != parsed:
            return None
    except Exception:
        return None
    return parsed


def _local_pptr(value):
    """Decode only an unambiguous local PPtr (FileID 0)."""
    value = unwrap(value)
    if not isinstance(value, dict):
        return None
    file_id = _strict_int(value.get("m_FileID", value.get("file_id", 0)))
    path_id = _strict_int(value.get("m_PathID", value.get("path_id", 0)))
    if file_id != 0 or path_id in (None, 0):
        return None
    return path_id


def _parameter_driver_writes(behaviour_obj, scripts):
    """Read a VRCAvatarParameterDriver without inferring missing fields.

    None means the behaviour could not be classified or parsed safely.  An
    empty list means it was a different, known StateMachineBehaviour.
    """
    script_name, header_shift = mono_script_location(behaviour_obj, scripts)
    if not script_name:
        return None
    if script_name != "VRCAvatarParameterDriver":
        return []
    if header_shift:
        try:
            raw = behaviour_obj.get_raw_data()
            repaired = raw[header_shift:] + bytes(header_shift)
            tree = read_typetree_bytes(
                behaviour_obj, behaviour_obj._get_typetree_node(None), repaired)
        except Exception:
            tree = None
    else:
        tree = read_typetree_safe(behaviour_obj)
    if not isinstance(tree, dict) or not isinstance(tree.get("parameters"), list):
        return None
    writes = []
    for raw_parameter in tree.get("parameters", []):
        parameter = unwrap(raw_parameter)
        if not isinstance(parameter, dict):
            return None
        name = fix(parameter.get("name", ""))
        source = fix(parameter.get("source", ""))
        parameter_type = _strict_int(parameter.get("type"))
        try:
            value = float(parameter.get("value", 0.0))
        except (TypeError, ValueError, OverflowError):
            return None
        if not name or parameter_type is None or not math.isfinite(value):
            return None
        write = {
            "name": name,
            "type": parameter_type,
            "value": value,
            "source": source,
        }
        # Absence is unknown, not false/zero: older graph caches do not carry
        # Copy range conversion or driver execution context.
        metadata = {}
        def serialized_bool(value):
            # Unity TypeTrees may expose bool fields as UInt8/int 0 or 1.
            # Accept that exact encoding, never generic truthiness ("false", 2).
            if isinstance(value, bool):
                return value
            if isinstance(value, int) and value in (0, 1):
                return bool(value)
            raise ValueError("invalid serialized Boolean")
        for field, output in (("convertRange", "convert_range"),
                              ("preventRepeats", "prevent_repeats")):
            if field in parameter:
                try:
                    metadata[output] = serialized_bool(parameter[field])
                except ValueError:
                    return None
        if "localOnly" in tree:
            try:
                metadata["local_only"] = serialized_bool(tree["localOnly"])
            except ValueError:
                return None
        for field, output in (("sourceMin", "source_min"), ("sourceMax", "source_max"),
                              ("destMin", "dest_min"), ("destMax", "dest_max"),
                              ("valueMin", "value_min"), ("valueMax", "value_max"),
                              ("chance", "chance")):
            if field not in parameter:
                continue
            if isinstance(parameter[field], bool):
                return None
            try:
                numeric = float(parameter[field])
            except (TypeError, ValueError, OverflowError):
                return None
            if not math.isfinite(numeric):
                return None
            metadata[output] = numeric
        if metadata:
            write["operation_metadata"] = metadata
        writes.append(write)
    return writes


def _state_parameter_write_map(obj, tree, scripts):
    """Map (layer index, full state path ID) to explicit driver writes.

    Unity stores this association through a range table, a behaviour-index
    vector, and a PPtr array.  Any malformed range, duplicate key, unresolved
    pointer, or unknown behaviour makes that state unavailable rather than
    inviting a guessed association.
    """
    description = unwrap(tree.get("m_StateMachineBehaviourVectorDescription", {}))
    behaviours = tree.get("m_StateMachineBehaviours", []) or []
    if not isinstance(description, dict) or not isinstance(behaviours, list):
        return {}
    ranges = description.get("m_StateMachineBehaviourRanges", []) or []
    indices = description.get("m_StateMachineBehaviourIndices", []) or []
    if not isinstance(ranges, list) or not isinstance(indices, list):
        return {}

    descriptors = {}
    ambiguous = set()
    for raw_range in ranges:
        if not isinstance(raw_range, (list, tuple)) or len(raw_range) != 2:
            continue
        key = unwrap(raw_range[0])
        span = unwrap(raw_range[1])
        if not isinstance(key, dict) or not isinstance(span, dict):
            continue
        layer_index = _strict_int(key.get("m_LayerIndex"))
        state_id = _strict_int(key.get("m_StateID"))
        start = _strict_int(span.get("m_StartIndex"))
        count = _strict_int(span.get("m_Count"))
        if (layer_index is None or state_id is None or start is None or
                count is None or layer_index < 0 or start < 0 or count < 0 or
                start + count > len(indices)):
            continue
        map_key = (layer_index, state_id)
        if map_key in descriptors:
            ambiguous.add(map_key)
            continue
        descriptors[map_key] = (start, count)

    objects = getattr(getattr(obj, "assets_file", None), "objects", None)
    if not isinstance(objects, dict):
        return {}
    cache = {}
    result = {}
    for map_key, (start, count) in descriptors.items():
        if map_key in ambiguous:
            continue
        writes = []
        valid = True
        for position in range(start, start + count):
            behaviour_index = _strict_int(unwrap(indices[position]))
            if (behaviour_index is None or behaviour_index < 0 or
                    behaviour_index >= len(behaviours)):
                valid = False
                break
            path_id = _local_pptr(behaviours[behaviour_index])
            behaviour_obj = objects.get(path_id) if path_id is not None else None
            if behaviour_obj is None:
                valid = False
                break
            if path_id not in cache:
                cache[path_id] = _parameter_driver_writes(behaviour_obj, scripts)
            parsed = cache[path_id]
            if parsed is None:
                valid = False
                break
            writes.extend(parsed)
        if valid:
            result[map_key] = writes
    return result


_RUNTIME_LAYER_BEHAVIOURS = {
    "VRCAnimatorLayerControl",
    "VRCPlayableLayerControl",
}


def _controller_parameter_read_evidence(obj, tree, scripts, tos):
    """Raw completeness/provenance for parameter consumers, not a lock verdict.

    Transition conditions alone omit state mirror/time/speed parameters and
    ParameterDriver Copy sources. Keep those independent reads visible to a
    native proof that needs a complete use census.
    """
    evidence = {"state_fields_complete": True, "driver_mapping_complete": True,
                "behaviour_scripts": [], "other_state_reads": []}
    controller = tree.get("m_Controller", {}) or {}
    required = {"m_SpeedParamID", "m_MirrorParamID", "m_CycleOffsetParamID", "m_TimeParamID"}
    state_coordinates = set()
    for mi, raw_machine in enumerate(controller.get("m_StateMachineArray", []) or []):
        machine = unwrap(raw_machine)
        if not isinstance(machine, dict):
            evidence["state_fields_complete"] = False
            continue
        for si, raw_state in enumerate(machine.get("m_StateConstantArray", []) or []):
            state = unwrap(raw_state)
            if not isinstance(state, dict) or not required.issubset(state):
                evidence["state_fields_complete"] = False
            if not isinstance(state, dict):
                continue
            state_id = _strict_int(state.get("m_FullPathID"))
            if state_id is not None:
                state_coordinates.add((mi, state_id))
            for field, raw in state.items():
                if not field.endswith("ParamID"):
                    continue
                value = _strict_int(raw)
                if value is None or not -(1 << 31) <= value <= 0xFFFFFFFF:
                    evidence["state_fields_complete"] = False
                    continue
                value &= 0xFFFFFFFF
                if value:
                    evidence["other_state_reads"].append({"machine_index": mi,
                        "state_index": si, "field": field, "parameter_hash": value,
                        "parameter": fix(tos.get(value, ""))})
    description = unwrap(tree.get("m_StateMachineBehaviourVectorDescription"))
    behaviours = tree.get("m_StateMachineBehaviours")
    if not isinstance(description, dict) or not isinstance(behaviours, list):
        evidence["driver_mapping_complete"] = False
        return evidence
    ranges = description.get("m_StateMachineBehaviourRanges")
    indices = description.get("m_StateMachineBehaviourIndices")
    if not isinstance(ranges, list) or not isinstance(indices, list):
        evidence["driver_mapping_complete"] = False
        return evidence
    objects = getattr(getattr(obj, "assets_file", None), "objects", {})
    objects = objects if isinstance(objects, dict) else {}
    seen_keys, visited, script_names = set(), set(), set()
    for raw_range in ranges:
        if not isinstance(raw_range, (list, tuple)) or len(raw_range) != 2:
            evidence["driver_mapping_complete"] = False
            continue
        key, span = map(unwrap, raw_range)
        if not isinstance(key, dict) or not isinstance(span, dict):
            evidence["driver_mapping_complete"] = False
            continue
        mi, sid = _strict_int(key.get("m_LayerIndex")), _strict_int(key.get("m_StateID"))
        start, count = _strict_int(span.get("m_StartIndex")), _strict_int(span.get("m_Count"))
        if (mi is None or sid is None or start is None or count is None or
                mi < 0 or start < 0 or count < 0 or start + count > len(indices) or
                (mi, sid) in seen_keys or (count > 0 and (mi, sid) not in state_coordinates)):
            evidence["driver_mapping_complete"] = False
            continue
        seen_keys.add((mi, sid))
        for offset in range(start, start + count):
            index = _strict_int(unwrap(indices[offset]))
            if index is None or not 0 <= index < len(behaviours):
                evidence["driver_mapping_complete"] = False
                continue
            pid = _local_pptr(behaviours[index])
            target = objects.get(pid)
            if target is None:
                evidence["driver_mapping_complete"] = False
                continue
            if pid in visited:
                continue
            visited.add(pid)
            script_name, _ = mono_script_location(target, scripts)
            if not script_name:
                evidence["driver_mapping_complete"] = False
                continue
            script_names.add(script_name)
            if _parameter_driver_writes(target, scripts) is None:
                evidence["driver_mapping_complete"] = False
    evidence["behaviour_scripts"] = sorted(script_names)
    return evidence


def _runtime_layer_behaviour(behaviour_obj, scripts):
    """Normalize VRChat behaviours that can change runtime layer activity.

    Returning None is deliberately ambiguous: either the object is unrelated
    or a relevant object could not be parsed.  The caller records diagnostics
    so downstream analysis never treats an incomplete scan as proof that a
    zero-weight layer cannot be activated.
    """
    script_name, _ = mono_script_location(behaviour_obj, scripts)
    if script_name not in _RUNTIME_LAYER_BEHAVIOURS:
        return None, script_name, True
    tree, confirmed_name = _read_named_mono_safe(
        behaviour_obj, scripts, _RUNTIME_LAYER_BEHAVIOURS)
    if not isinstance(tree, dict) or confirmed_name != script_name:
        return None, script_name, False

    enabled = _strict_int(tree.get("m_Enabled", 1))
    layer = _strict_int(tree.get("layer"))
    try:
        goal_weight = float(tree.get("goalWeight"))
        blend_duration = float(tree.get("blendDuration", 0.0))
    except (TypeError, ValueError, OverflowError):
        return None, script_name, False
    if (enabled is None or layer is None or layer < 0 or
            not math.isfinite(goal_weight) or
            not math.isfinite(blend_duration) or blend_duration < 0.0):
        return None, script_name, False

    result = {
        "script": script_name,
        "enabled": bool(enabled),
        "layer": layer,
        "goal_weight": goal_weight,
        "blend_duration": blend_duration,
    }
    if script_name == "VRCAnimatorLayerControl":
        playable = _strict_int(tree.get("playable"))
        if playable is None:
            return None, script_name, False
        result["playable"] = playable
    return result, script_name, True


def _state_runtime_behaviour_map(obj, tree, scripts):
    """Map serialized states to normalized layer-control behaviours.

    The mapping uses the same range/index/PPtr chain as parameter drivers.
    Diagnostics are emitted at controller level because an unresolved pointer
    must not be silently interpreted as evidence that no LayerControl exists.
    """
    diagnostics = {
        "mapping_complete": True,
        "pointer_count": 0,
        "relevant_count": 0,
        "parsed_count": 0,
        "error_count": 0,
    }
    description = unwrap(tree.get("m_StateMachineBehaviourVectorDescription", {}))
    behaviours = tree.get("m_StateMachineBehaviours", []) or []
    if not isinstance(description, dict) or not isinstance(behaviours, list):
        diagnostics["mapping_complete"] = False
        diagnostics["error_count"] = 1
        return {}, diagnostics
    ranges = description.get("m_StateMachineBehaviourRanges", []) or []
    indices = description.get("m_StateMachineBehaviourIndices", []) or []
    if not isinstance(ranges, list) or not isinstance(indices, list):
        diagnostics["mapping_complete"] = False
        diagnostics["error_count"] = 1
        return {}, diagnostics

    objects = getattr(getattr(obj, "assets_file", None), "objects", None)
    if not isinstance(objects, dict):
        diagnostics["mapping_complete"] = False
        diagnostics["error_count"] = 1
        return {}, diagnostics

    result = {}
    seen_keys = set()
    cache = {}
    for raw_range in ranges:
        if not isinstance(raw_range, (list, tuple)) or len(raw_range) != 2:
            diagnostics["mapping_complete"] = False
            diagnostics["error_count"] += 1
            continue
        key = unwrap(raw_range[0])
        span = unwrap(raw_range[1])
        if not isinstance(key, dict) or not isinstance(span, dict):
            diagnostics["mapping_complete"] = False
            diagnostics["error_count"] += 1
            continue
        layer_index = _strict_int(key.get("m_LayerIndex"))
        state_id = _strict_int(key.get("m_StateID"))
        start = _strict_int(span.get("m_StartIndex"))
        count = _strict_int(span.get("m_Count"))
        map_key = (layer_index, state_id)
        if (layer_index is None or layer_index < 0 or state_id is None or
                start is None or start < 0 or count is None or count < 0 or
                start + count > len(indices) or map_key in seen_keys):
            diagnostics["mapping_complete"] = False
            diagnostics["error_count"] += 1
            continue
        seen_keys.add(map_key)
        normalized = []
        for position in range(start, start + count):
            diagnostics["pointer_count"] += 1
            behaviour_index = _strict_int(unwrap(indices[position]))
            if (behaviour_index is None or behaviour_index < 0 or
                    behaviour_index >= len(behaviours)):
                diagnostics["mapping_complete"] = False
                diagnostics["error_count"] += 1
                continue
            path_id = _local_pptr(behaviours[behaviour_index])
            behaviour_obj = objects.get(path_id) if path_id is not None else None
            if behaviour_obj is None:
                diagnostics["mapping_complete"] = False
                diagnostics["error_count"] += 1
                continue
            if path_id not in cache:
                cache[path_id] = _runtime_layer_behaviour(behaviour_obj, scripts)
            parsed, script_name, complete = cache[path_id]
            if script_name in _RUNTIME_LAYER_BEHAVIOURS:
                diagnostics["relevant_count"] += 1
            if not complete:
                diagnostics["mapping_complete"] = False
                diagnostics["error_count"] += 1
            if parsed is not None:
                diagnostics["parsed_count"] += 1
                normalized.append(parsed)
        if normalized:
            result[map_key] = normalized
    return result, diagnostics


def _layer_default_weight(controller, machine_index):
    layers = controller.get("m_LayerArray", []) or []
    if not isinstance(layers, list) or machine_index >= len(layers):
        return None
    layer = unwrap(layers[machine_index])
    if not isinstance(layer, dict):
        return None
    linked_machine = _strict_int(layer.get("m_StateMachineIndex"))
    if linked_machine != machine_index:
        return None
    try:
        weight = float(layer.get("m_DefaultWeight"))
    except (TypeError, ValueError, OverflowError):
        return None
    return weight if math.isfinite(weight) else None


def _controller_parameter_defaults(controller, tos):
    values = unwrap(controller.get("m_Values", {}))
    defaults = unwrap(controller.get("m_DefaultValues", {}))
    if not isinstance(values, dict) or not isinstance(defaults, dict):
        return []
    value_array = values.get("m_ValueArray", []) or []
    if not isinstance(value_array, list):
        return []
    typed = {
        1: ("float", defaults.get("m_FloatValues", []) or []),
        3: ("int", defaults.get("m_IntValues", []) or []),
        4: ("bool", defaults.get("m_BoolValues", []) or []),
    }
    offsets = {kind: 0 for kind in typed}
    result = []
    for raw_value in value_array:
        value = unwrap(raw_value)
        if not isinstance(value, dict):
            continue
        value_id = _strict_int(value.get("m_ID"))
        value_type = _strict_int(value.get("m_Type"))
        if value_id is None or value_type not in typed:
            continue
        kind, source = typed[value_type]
        index = offsets[value_type]
        offsets[value_type] = index + 1
        if not isinstance(source, list) or index >= len(source):
            continue
        default = source[index]
        if kind == "bool":
            default = bool(default)
        elif kind == "int":
            default = _strict_int(default)
            if default is None:
                continue
        else:
            try:
                default = float(default)
            except (TypeError, ValueError, OverflowError):
                continue
            if not math.isfinite(default):
                continue
        name = fix(tos.get(value_id, ""))
        if not name:
            continue
        result.append({"name": name, "type": kind, "default": default})
    return result


def _finite_float_list(value, limit=1000000):
    """Decode a bounded serialized float vector without guessing bad values."""
    value = unwrap(value)
    if not isinstance(value, list) or len(value) > limit:
        return None
    result = []
    for item in value:
        try:
            item = float(unwrap(item))
        except (TypeError, ValueError, OverflowError):
            return None
        if not math.isfinite(item):
            return None
        result.append(item)
    return result


def _animation_clip_constant_writes(tree, tos, resource_attribute_maps=None):
    """Return explicit scalar writes from one AnimationClip constant section.

    AnimationClip stores one ordered GenericBinding table for its streamed,
    dense and constant curves.  ConstantClip values therefore begin after the
    streamed and dense curve counts; pairing them with binding zero works only
    for very simple clips.  Resolve path/attribute hashes through the owning
    AnimatorController's TOS while retaining the hashes for lossless consumers.

    An inconsistent count makes the clip unavailable.  We deliberately do not
    infer vector widths, repair malformed bindings, or sample time-varying
    curves here: this field represents only serialized constant writes.
    """
    if not isinstance(tree, dict):
        return []
    binding_constant = unwrap(tree.get("m_ClipBindingConstant", {}))
    muscle_clip = unwrap(tree.get("m_MuscleClip", {}))
    clip = unwrap(muscle_clip.get("m_Clip", {})) \
        if isinstance(muscle_clip, dict) else None
    clip = unwrap(clip)
    # Unity 2022 may wrap the Clip payload in a non-transparent ``data``
    # member alongside bookkeeping fields.  ``unwrap`` intentionally only
    # removes one-field wrappers, so handle this documented nested shape
    # explicitly without guessing any offsets.
    if isinstance(clip, dict) and "m_ConstantClip" not in clip:
        nested_clip = unwrap(clip.get("data"))
        if isinstance(nested_clip, dict):
            clip = nested_clip
    if not isinstance(binding_constant, dict) or not isinstance(clip, dict):
        return []
    bindings = binding_constant.get("genericBindings", []) or []
    if not isinstance(bindings, list) or len(bindings) > 1000000:
        return []

    streamed = unwrap(clip.get("m_StreamedClip", {}))
    dense = unwrap(clip.get("m_DenseClip", {}))
    constant = unwrap(clip.get("m_ConstantClip", {}))
    if not isinstance(streamed, dict) or not isinstance(dense, dict):
        return []
    streamed_count = _strict_int(streamed.get("curveCount", 0))
    dense_count = _strict_int(dense.get("m_CurveCount", 0))
    constant_values = constant.get("data", []) \
        if isinstance(constant, dict) else constant
    values = _finite_float_list(constant_values)
    if (streamed_count is None or dense_count is None or values is None or
            streamed_count < 0 or dense_count < 0):
        return []
    first_binding = streamed_count + dense_count
    if first_binding < 0 or first_binding + len(values) > len(bindings):
        return []

    writes = []
    for value_index, value in enumerate(values):
        binding = unwrap(bindings[first_binding + value_index])
        if not isinstance(binding, dict):
            return []
        path_hash = _strict_int(binding.get("path"))
        attribute_hash = _strict_int(binding.get("attribute"))
        type_id = _strict_int(binding.get("typeID"))
        custom_type = _strict_int(binding.get("customType", 0))
        is_pptr = _strict_int(binding.get("isPPtrCurve", 0))
        is_int = _strict_int(binding.get("isIntCurve", 0))
        if None in (path_hash, attribute_hash, type_id, custom_type,
                    is_pptr, is_int):
            return []
        # PPtr values live in pptrCurveMapping rather than ConstantClip.data;
        # accepting one here would turn a float table index into a fake value.
        if is_pptr:
            continue
        attribute = fix(tos.get(attribute_hash, ""))
        path = fix(tos.get(path_hash, "")) if path_hash else ""
        # Activation curves are needed to distinguish a truly forced Contact
        # gate from a generated lock that pulses a nested Contact Sender.
        # Controller TOS tables frequently omit these two built-in property
        # names, but their Animator hashes are stable CRC32 values.
        activation_attributes = {
            zlib.crc32(b"m_Enabled") & 0xFFFFFFFF: "m_Enabled",
            zlib.crc32(b"m_IsActive") & 0xFFFFFFFF: "m_IsActive",
        }
        if not attribute:
            attribute = activation_attributes.get(attribute_hash, "")
        if (not attribute and resource_attribute_maps and
                ((custom_type == 20 and type_id == 137) or
                 (custom_type == 22 and type_id in (23, 137)))):
            candidates = resource_attribute_maps.get(custom_type, {}).get(attribute_hash, ())
            if isinstance(candidates, str):
                candidates = (candidates,)
            if len(candidates) == 1:
                attribute = candidates[0]
        # The snapshot is a semantic controller graph, not a replacement for
        # an AnimationClip dumper.  Emit only bindings the controller mapping
        # can name; unresolved material/transform curves are both enormous and
        # unusable for state-machine reasoning.  Preserve hashes on every
        # emitted record so consumers can still disambiguate equal names.
        if not attribute and not path:
            continue
        writes.append({
            "name": attribute,
            "attribute": attribute,
            "attribute_hash": attribute_hash,
            "path": path,
            "path_hash": path_hash,
            "type_id": type_id,
            "custom_type": custom_type,
            "is_int_curve": bool(is_int),
            "value": value,
            "constant_index": value_index,
            "binding_index": first_binding + value_index,
        })
    return writes


def _float_from_u32_bits(value):
    """Decode one serialized IEEE-754 word without using host byte order."""
    try:
        value = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if value < 0 or value > 0xFFFFFFFF:
        return None
    return struct.unpack("<f", struct.pack("<I", value))[0]


def _animation_clip_stable_streamed_writes(tree, tos):
    """Return provably constant activation writes stored in StreamedClip.

    Unity serializes each streamed frame as ``time, key-count`` followed by
    ``curve-index, coefficient[4]`` records.  A record is accepted only when
    every finite frame has a zero polynomial and the same exact boolean value.
    Time-varying curves, malformed frames and non-activation bindings fail
    closed instead of being sampled or inferred.
    """
    if not isinstance(tree, dict):
        return []
    binding_constant = unwrap(tree.get("m_ClipBindingConstant", {}))
    muscle_clip = unwrap(tree.get("m_MuscleClip", {}))
    clip = unwrap(muscle_clip.get("m_Clip", {})) \
        if isinstance(muscle_clip, dict) else None
    clip = unwrap(clip)
    if isinstance(clip, dict) and "m_StreamedClip" not in clip:
        nested_clip = unwrap(clip.get("data"))
        if isinstance(nested_clip, dict):
            clip = nested_clip
    if not isinstance(binding_constant, dict) or not isinstance(clip, dict):
        return []
    bindings = binding_constant.get("genericBindings", []) or []
    streamed = unwrap(clip.get("m_StreamedClip", {}))
    if not isinstance(bindings, list) or not isinstance(streamed, dict):
        return []
    curve_count = _strict_int(streamed.get("curveCount", 0))
    raw_words = unwrap(streamed.get("data", []))
    if (curve_count is None or curve_count <= 0 or curve_count > 1000000 or
            curve_count > len(bindings) or not isinstance(raw_words, list) or
            len(raw_words) > 1000000):
        return []
    words = []
    for raw_word in raw_words:
        word = _strict_int(unwrap(raw_word))
        if word is None or word < 0 or word > 0xFFFFFFFF:
            return []
        words.append(word)

    samples = {}
    position = 0
    saw_terminal = False
    while position < len(words):
        if position + 2 > len(words):
            return []
        frame_time = _float_from_u32_bits(words[position])
        key_count = words[position + 1]
        position += 2
        if frame_time is None or math.isnan(frame_time):
            return []
        if math.isinf(frame_time):
            if frame_time < 0 or key_count != 0 or position != len(words):
                return []
            saw_terminal = True
            break
        if key_count > curve_count or position + key_count * 5 > len(words):
            return []
        frame_indexes = set()
        for _ in range(key_count):
            curve_index = words[position]
            coefficients = [
                _float_from_u32_bits(value)
                for value in words[position + 1:position + 5]
            ]
            position += 5
            if (curve_index >= curve_count or curve_index in frame_indexes or
                    any(value is None or not math.isfinite(value)
                        for value in coefficients)):
                return []
            frame_indexes.add(curve_index)
            samples.setdefault(curve_index, []).append(coefficients)
    if position != len(words) or not samples:
        return []
    # Current Unity clips terminate with +inf/zero.  Requiring the sentinel
    # keeps truncated attacker-controlled vectors from being called stable.
    if not saw_terminal:
        return []

    activation_attributes = {
        zlib.crc32(b"m_Enabled") & 0xFFFFFFFF: "m_Enabled",
        zlib.crc32(b"m_IsActive") & 0xFFFFFFFF: "m_IsActive",
    }
    writes = []
    for curve_index, rows in sorted(samples.items()):
        binding = unwrap(bindings[curve_index])
        if not isinstance(binding, dict):
            return []
        path_hash = _strict_int(binding.get("path"))
        attribute_hash = _strict_int(binding.get("attribute"))
        type_id = _strict_int(binding.get("typeID"))
        custom_type = _strict_int(binding.get("customType", 0))
        is_pptr = _strict_int(binding.get("isPPtrCurve", 0))
        is_int = _strict_int(binding.get("isIntCurve", 0))
        if None in (path_hash, attribute_hash, type_id, custom_type,
                    is_pptr, is_int):
            return []
        attribute = activation_attributes.get(attribute_hash & 0xFFFFFFFF, "")
        if not attribute or is_pptr:
            continue
        value = rows[0][3]
        if not (abs(value) <= 1e-7 or abs(value - 1.0) <= 1e-7):
            continue
        value = 0.0 if abs(value) <= 1e-7 else 1.0
        if any(
                any(abs(coefficient) > 1e-7 for coefficient in row[:3]) or
                abs(row[3] - value) > 1e-7
                for row in rows):
            continue
        writes.append({
            "name": attribute,
            "attribute": attribute,
            "attribute_hash": attribute_hash,
            "path": fix(tos.get(path_hash, "")) if path_hash else "",
            "path_hash": path_hash,
            "type_id": type_id,
            "custom_type": custom_type,
            "is_int_curve": bool(is_int),
            "value": value,
            "streamed_curve_index": curve_index,
            "binding_index": curve_index,
            "source": "animation_stable_streamed_clip",
        })
    return writes


def _state_clip_ids(state):
    """Enumerate referenced controller clip indices from a state."""
    result = []
    for raw_tree in state.get("m_BlendTreeConstantArray", []) or []:
        tree = unwrap(raw_tree)
        if not isinstance(tree, dict):
            continue
        for raw_node in tree.get("m_NodeArray", []) or []:
            node = unwrap(raw_node)
            if not isinstance(node, dict):
                continue
            clip_id = _strict_int(node.get("m_ClipID"))
            if clip_id is not None and clip_id >= 0:
                result.append(clip_id)
    return result


def _state_direct_blend_reads(state, tos):
    """Return Direct Blend Tree parameter-to-child dependencies.

    A direct child weight is a real Animator parameter consumer even though it
    does not appear in transition conditions.  Keeping this edge lets the
    native reverse slice connect a keypad success latch to the animation clip
    that restores the restricted objects.
    """
    result = []
    for tree_index, raw_tree in enumerate(
            state.get("m_BlendTreeConstantArray", []) or []):
        tree = unwrap(raw_tree)
        if not isinstance(tree, dict):
            continue
        nodes = [unwrap(item) for item in tree.get("m_NodeArray", []) or []]
        for node_index, node in enumerate(nodes):
            if not isinstance(node, dict) or _strict_int(
                    node.get("m_BlendType")) != 4:
                continue
            direct = unwrap(node.get("m_BlendDirectData", {}))
            if not isinstance(direct, dict):
                continue
            child_indices = node.get("m_ChildIndices", []) or []
            event_ids = direct.get("m_ChildBlendEventIDArray", []) or []
            if len(child_indices) != len(event_ids):
                continue
            for child_index, event_id in zip(child_indices, event_ids):
                child_index = _strict_int(child_index)
                event_id = _strict_int(event_id)
                if (child_index is None or event_id is None or
                        child_index < 0 or child_index >= len(nodes)):
                    continue
                child = nodes[child_index]
                if not isinstance(child, dict):
                    continue
                parameter = fix(tos.get(event_id & 0xFFFFFFFF, ""))
                if not parameter:
                    continue
                result.append({
                    "parameter": parameter,
                    "parameter_hash": event_id & 0xFFFFFFFF,
                    "tree_index": tree_index,
                    "node_index": node_index,
                    "child_node_index": child_index,
                    "clip_id": _strict_int(child.get("m_ClipID")),
                })
    return result


def _state_blend_parameter_reads(state, tos):
    """Return parameter-to-leaf dependencies for Direct and 1D trees.

    Parameter Compressor/d4rkAvatarOptimizer commonly nests a page-selecting
    1D tree inside another 1D tree.  Treating only Direct Blend Trees as
    consumers loses the terminal menu parameter even though it selects the
    animation clips that apply the final avatar effects.  Keep every exact
    parameter -> child -> descendant-clip edge; the native side still treats
    these as conservative dependencies, not as runtime proof by themselves.
    """
    result = list(_state_direct_blend_reads(state, tos))
    seen = {
        (item.get("parameter_hash"), item.get("tree_index"),
         item.get("node_index"), item.get("child_node_index"),
         item.get("clip_id"))
        for item in result
    }
    for tree_index, raw_tree in enumerate(
            state.get("m_BlendTreeConstantArray", []) or []):
        tree = unwrap(raw_tree)
        if not isinstance(tree, dict):
            continue
        nodes = [unwrap(item) for item in tree.get("m_NodeArray", []) or []]

        def descendant_clips(root_index):
            pending = [root_index]
            visited = set()
            clips = set()
            while pending and len(visited) <= len(nodes):
                index = pending.pop()
                if index in visited or index < 0 or index >= len(nodes):
                    continue
                visited.add(index)
                node = nodes[index]
                if not isinstance(node, dict):
                    continue
                clip_id = _strict_int(node.get("m_ClipID"))
                if clip_id is not None and 0 <= clip_id < 0xFFFFFFFF:
                    clips.add(clip_id)
                for child in node.get("m_ChildIndices", []) or []:
                    child = _strict_int(child)
                    if child is not None:
                        pending.append(child)
            return sorted(clips)

        for node_index, node in enumerate(nodes):
            if not isinstance(node, dict) or _strict_int(
                    node.get("m_BlendType")) != 0:
                continue
            event_id = _strict_int(node.get("m_BlendEventID"))
            if event_id is None:
                continue
            parameter = fix(tos.get(event_id & 0xFFFFFFFF, ""))
            if not parameter:
                continue
            child_indices = node.get("m_ChildIndices", []) or []
            blend_1d = unwrap(node.get("m_Blend1dData", {}))
            thresholds = (blend_1d.get("m_ChildThresholdArray", []) or []) \
                if isinstance(blend_1d, dict) else []
            if len(child_indices) != len(thresholds):
                continue
            for child_index, threshold in zip(child_indices, thresholds):
                child_index = _strict_int(child_index)
                try:
                    threshold = float(threshold)
                except (TypeError, ValueError, OverflowError):
                    continue
                if (child_index is None or not math.isfinite(threshold) or
                        child_index < 0 or child_index >= len(nodes)):
                    continue
                for clip_id in descendant_clips(child_index):
                    signature = (event_id & 0xFFFFFFFF, tree_index,
                                 node_index, child_index, clip_id)
                    if signature in seen:
                        continue
                    seen.add(signature)
                    result.append({
                        "parameter": parameter,
                        "parameter_hash": event_id & 0xFFFFFFFF,
                        "tree_index": tree_index,
                        "node_index": node_index,
                        "child_node_index": child_index,
                        "clip_id": clip_id,
                        "blend_type": "1d",
                        "threshold": threshold,
                    })
    return result


class _ClipProjectionUnsupported(ValueError):
    pass


def _read_clip_evidence_tree(obj, include_streamed=False, *, raw_data=None,
                             nodes=None, repair_tail_bytes=0):
    """Read exactly the fields consumed by clip evidence, with checked skips.

    Large editor/dense curves are not evidence inputs. Walk their real TypeTree
    layout without building millions of Python objects. Never enables Boost.
    """
    if not callable(getattr(obj, "_get_typetree_node", None)) or not hasattr(obj, "assets_file"):
        raise _ClipProjectionUnsupported("clip reader has no TypeTree projection API")
    from UnityPy.helpers import TypeTreeHelper as helper
    from UnityPy.streams import EndianBinaryReader
    raw = bytes(obj.get_raw_data() if raw_data is None else raw_data)
    reader = EndianBinaryReader(raw, endian=getattr(obj.reader, "endian", "<"))
    config = helper.TypeTreeConfig(True, obj.assets_file, False)
    root = obj._get_typetree_node(None) if nodes is None else nodes
    repaired_tail_verified = not repair_tail_bytes
    widths = {"SInt8": 1, "UInt8": 1, "char": 1, "bool": 1,
              "short": 2, "SInt16": 2, "unsigned short": 2, "UInt16": 2,
              "int": 4, "SInt32": 4, "unsigned int": 4, "UInt32": 4,
              "Type*": 4, "float": 4, "long long": 8, "SInt64": 8,
              "unsigned long long": 8, "UInt64": 8, "FileSize": 8, "double": 8}
    descriptions, strides = {}, {}

    def describe(node):
        key = id(node)
        if key not in descriptions:
            descriptions[key] = (node, node.m_Type, tuple(node.m_Children),
                                 bool((node.m_MetaFlag or 0) & 0x4000))
        return descriptions[key][1:]

    def advance(size):
        if size < 0 or size > len(raw) - reader.Position:
            raise ValueError("clip TypeTree range exceeds object")
        reader.Position += size

    def align():
        advance((-reader.Position) % 4)

    def count():
        if len(raw) - reader.Position < 4:
            raise ValueError("truncated clip array size")
        size = reader.read_int()
        if size < 0:
            raise ValueError("negative clip array size")
        return size

    def stride(node, phase, depth=0, ignore_outer_alignment=False):
        if depth > 128:
            raise _ClipProjectionUnsupported("clip TypeTree too deep")
        key = (id(node), phase, ignore_outer_alignment)
        if key in strides:
            return strides[key]
        kind, children, aligned = describe(node)
        if kind in widths:
            size = widths[kind]
        elif kind in ("string", "TypelessData", "ReferencedObject", "ReferencedObjectData", "ManagedReferencesRegistry") or (children and children[0].m_Type == "Array"):
            size = None
        else:
            size = 0
            for child in children:
                child_size = stride(child, (phase + size) % 4, depth + 1)
                if child_size is None:
                    size = None
                    break
                size += child_size
        if size is not None and aligned and not ignore_outer_alignment:
            size += (-(phase + size)) % 4
        strides[key] = size
        return size

    def skip(node, depth=0, ignore_outer_alignment=False):
        if depth > 128:
            raise _ClipProjectionUnsupported("clip TypeTree too deep")
        size = stride(node, reader.Position % 4, ignore_outer_alignment=ignore_outer_alignment)
        if size is not None:
            advance(size)
            return
        kind, children, aligned = describe(node)
        if ignore_outer_alignment:
            aligned = False
        if kind in ("ReferencedObject", "ReferencedObjectData", "ManagedReferencesRegistry"):
            raise _ClipProjectionUnsupported("managed reference in clip")
        if kind in ("string", "TypelessData"):
            size = count()
            advance(size)
            if kind == "string" and size:
                align()
        elif children and children[0].m_Type == "Array":
            array = children[0]
            if len(array.m_Children) != 2:
                raise _ClipProjectionUnsupported("unexpected clip array layout")
            aligned |= bool((array.m_MetaFlag or 0) & 0x4000)
            size = count()
            element = array.m_Children[1]
            element_kind, element_children, element_aligned = describe(element)
            if element_aligned and (element_kind in ("pair", "ReferencedObject") or
                                    (element_children and element_children[0].m_Type == "Array")):
                # Do not enter a materializing reader for an unbounded special
                # layout. An unsupported object is missing evidence, not empty.
                raise _ClipProjectionUnsupported("special aligned clip array")
            aligned |= element_aligned
            phases = [stride(element, phase, ignore_outer_alignment=element_aligned) for phase in range(4)]
            if all(value is not None for value in phases):
                if size and min(phases) <= 0:
                    raise _ClipProjectionUnsupported("zero-width clip array element")
                # Fixed layouts can have per-element padding. Follow their
                # modulo-4 cycle rather than assuming byte_size * count.
                visited = {}
                remaining = size
                while remaining:
                    phase = reader.Position % 4
                    if phase in visited:
                        old_remaining, old_position = visited[phase]
                        cycle = old_remaining - remaining
                        cycles = remaining // cycle
                        if cycles:
                            jump = (reader.Position - old_position) * cycles
                            if jump > len(raw) - reader.Position:
                                raise ValueError("clip array exceeds object: field=%s type=%s count=%d offset=%d bytes=%d remaining=%d" %
                                    (node.m_Name, element_kind, size, reader.Position, jump, len(raw) - reader.Position))
                            advance(jump)
                            remaining -= cycle * cycles
                            continue
                    visited[phase] = (remaining, reader.Position)
                    advance(phases[phase])
                    remaining -= 1
            else:
                for _ in range(size):
                    before = reader.Position
                    skip(element, depth + 1, ignore_outer_alignment=element_aligned)
                    if reader.Position == before:
                        raise _ClipProjectionUnsupported("non-progressing variable clip array")
        else:
            for child in children:
                skip(child, depth + 1)
        if aligned:
            align()

    def project(node, selection, depth=0):
        nonlocal repaired_tail_verified
        if depth > 128:
            raise _ClipProjectionUnsupported("clip evidence nesting too deep")
        if selection is True:
            kind, children, aligned = describe(node)
            if children and children[0].m_Type == "Array" and len(children[0].m_Children) == 2:
                array = children[0]
                element = array.m_Children[1]
                element_kind, _, element_aligned = describe(element)
                bulk = helper.FUNCTION_READ_MAP_ARRAY.get(element_kind)
                if bulk and element_kind in widths and not element_aligned:
                    size = count()
                    if size > (len(raw) - reader.Position) // widths[element_kind]:
                        raise ValueError("clip evidence array exceeds object")
                    value = list(bulk(reader, size))
                    if aligned or bool((array.m_MetaFlag or 0) & 0x4000):
                        align()
                    return value
            # Bound every variable-length field before materializing selected
            # evidence. A bogus binding/event count must not cause an unbounded
            # allocation in the otherwise checked Python TypeTree reader.
            begin = reader.Position
            skip(node)
            expected_end = reader.Position
            reader.Position = begin
            value = helper.read_value(node, reader, config)
            if reader.Position != expected_end:
                raise ValueError("clip evidence layout disagrees with checked traversal")
            if not 0 <= reader.Position <= len(raw):
                raise ValueError("clip evidence exceeds object")
            return value
        kind, children, aligned = describe(node)
        if not children or children[0].m_Type == "Array":
            raise _ClipProjectionUnsupported("unexpected evidence container")
        if len(children) == 1 and children[0].m_Name == "data" and "data" not in selection:
            result = {"data": project(children[0], selection, depth + 1)}
            if aligned:
                align()
            return result
        result = {}
        for child in children:
            wanted = selection.get(child.m_Name)
            if wanted is not None:
                result[child.m_Name] = project(child, wanted, depth + 1)
            else:
                begin = reader.Position
                skip(child)
                if (repair_tail_bytes and node is root and child is children[-1]
                        and child.m_Name == "m_Events"):
                    # Prefix-shifted objects can lose a few trailing bytes.
                    # Only reconstruct zeros inside the final EMPTY event-list
                    # count/padding. Never synthesize a curve, binding, value,
                    # or an event body from truncated data.
                    _, event_children, _ = describe(child)
                    if (event_children and event_children[0].m_Type == "Array"
                            and len(event_children[0].m_Children) == 2
                            and event_children[0].m_Children[1].m_Type == "AnimationEvent"
                            and begin < len(raw) - repair_tail_bytes
                            and 4 <= reader.Position - begin <= 7
                            and reader.Position == len(raw)
                            and raw[begin:] == bytes(len(raw) - begin)):
                        repaired_tail_verified = True
        if aligned:
            align()
        return result

    streamed = {"curveCount": True, "discreteCurveCount": True}
    if include_streamed:
        streamed["data"] = True
    clip = {"m_StreamedClip": streamed, "m_DenseClip": {"m_CurveCount": True},
            "m_ConstantClip": True}
    wrapped_clip = dict(clip, data=clip)
    selection = {"m_Name": True, "m_ClipBindingConstant": True,
                 "m_MuscleClip": {"m_Clip": wrapped_clip}}
    result = project(root, selection)
    if reader.Position != len(raw):
        raise ValueError("clip evidence reader did not consume exact object")
    if not repaired_tail_verified:
        raise ValueError("clip prefix repair would synthesize non-padding evidence")
    muscle = unwrap(result.get("m_MuscleClip", {}))
    payload = unwrap(muscle.get("m_Clip", {})) if isinstance(muscle, dict) else {}
    if isinstance(payload, dict) and "m_ConstantClip" not in payload:
        payload = unwrap(payload.get("data"))
    if not isinstance(payload, dict) or "m_ConstantClip" not in payload or "m_ClipBindingConstant" not in result:
        raise _ClipProjectionUnsupported("clip evidence layout not recognized")
    return result


def _read_clip_evidence_with_prefix_recovery(obj, include_streamed=False):
    """Checked projection and unique, bounded junk-prefix recovery.

    No source bytes are modified. Every accepted interpretation must consume
    the complete object; no animation evidence is reconstructed from zeros.
    """
    raw = bytes(obj.get_raw_data())
    endian = ">" if getattr(obj.reader, "endian", "<") == ">" else "<"

    def plausible_name(offset):
        if len(raw) - offset < 4:
            return False
        size = struct.unpack_from(endian + "i", raw, offset)[0]
        if not 0 <= size <= len(raw) - offset - 4:
            return False
        name = raw[offset + 4:offset + 4 + size]
        if b"\0" in name:
            return False
        try:
            name.decode("utf-8", "strict")
            return True
        except UnicodeDecodeError:
            return False

    if plausible_name(0):
        # An ordinary, plausible header must never be reinterpreted after a
        # later corruption. The sole exception is an empty name: a leading
        # zero prefix on a big-endian object also looks like an empty name.
        try:
            return _read_clip_evidence_tree(obj, include_streamed, raw_data=raw)
        except (ValueError, struct.error):
            if struct.unpack_from(endian + "i", raw, 0)[0] != 0:
                raise
    candidates = []
    for shift in range(1, 5):
        if not plausible_name(shift):
            continue
        try:
            tree = _read_clip_evidence_tree(obj, include_streamed,
                raw_data=raw[shift:] + bytes(shift), repair_tail_bytes=shift)
        except (ValueError, _ClipProjectionUnsupported, struct.error):
            continue
        candidates.append(tree)
    if len(candidates) != 1:
        raise ValueError("clip header has no unique complete bounded interpretation")
    return candidates[0]


def _controller_clip_constant_reader(obj, tree, tos,
                                     activation_path_hashes=None,
                                     parameter_attribute_hashes=None,
                                     include_stable_streamed=False,
                                     activation_attribute_only=False,
                                     resource_attribute_maps=None):
    """Build a lazy, per-controller AnimationClip constant-curve reader."""
    pointers = tree.get("m_AnimationClips", []) or []
    if not isinstance(pointers, list):
        pointers = []
    objects = getattr(getattr(obj, "assets_file", None), "objects", None)
    objects = objects if isinstance(objects, dict) else {}
    cache = {}
    object_cache = {}
    activation_filter_enabled = (
        activation_path_hashes is not None or activation_attribute_only)
    activation_path_hashes = {
        int(value) & 0xFFFFFFFF for value in (activation_path_hashes or [])
    }
    activation_attribute_hashes = {
        zlib.crc32(b"m_Enabled") & 0xFFFFFFFF,
        zlib.crc32(b"m_IsActive") & 0xFFFFFFFF,
    }
    parameter_filter_enabled = parameter_attribute_hashes is not None
    parameter_attribute_hashes = {
        int(value) & 0xFFFFFFFF
        for value in (parameter_attribute_hashes or [])
    }

    def read(clip_id):
        if clip_id in cache:
            return cache[clip_id]
        result = []
        if clip_id < 0 or clip_id >= len(pointers):
            cache[clip_id] = result
            return result
        path_id = _local_pptr(pointers[clip_id])
        clip_obj = objects.get(path_id) if path_id is not None else None
        if clip_obj is None or clip_obj.type.name != "AnimationClip":
            cache[clip_id] = result
            return result
        if activation_filter_enabled or parameter_filter_enabled:
            # Contact classification needs only activation curves on the
            # exact Sender hierarchy.  GenericBinding stores both hashes in
            # the serialized bytes, so reject unrelated clothing/expression
            # clips before the expensive TypeTree materialization.
            try:
                raw = bytes(clip_obj.get_raw_data())
                endian = ">" if getattr(clip_obj.reader, "endian", "<") == ">" else "<"
                has_path = bool(activation_path_hashes) and any(
                    struct.pack(endian + "I", value) in raw
                    for value in activation_path_hashes)
                has_activation = any(
                    struct.pack(endian + "I", value) in raw
                    for value in activation_attribute_hashes)
                has_parameter = bool(parameter_attribute_hashes) and any(
                    struct.pack(endian + "I", value) in raw
                    for value in parameter_attribute_hashes)
                activation_match = (
                    has_activation if activation_attribute_only
                    else (has_path and has_activation))
                if not (has_parameter or activation_match):
                    cache[clip_id] = result
                    return result
            except Exception:
                cache[clip_id] = result
                return result
        if callable(getattr(clip_obj, "_get_typetree_node", None)) and hasattr(clip_obj, "assets_file"):
            try:
                clip_tree = _read_clip_evidence_with_prefix_recovery(
                    clip_obj, include_stable_streamed)
            except Exception as error:
                # A declared deep-evidence state must not silently acquire an
                # empty write list when its animation could not be decoded.
                raise ValueError("动画证据读取失败（AnimationClip %s）；未生成完整图谱" % path_id) from error
        else:
            # Minimal object adapters used by older integrations/tests expose
            # only read_typetree. Real UnityPy ObjectReaders take the branch
            # above, with bounds checked before every materialization.
            clip_tree = read_typetree_safe(clip_obj)
        if not isinstance(clip_tree, dict):
            raise ValueError("动画证据读取失败（AnimationClip %s）；未生成完整图谱" % path_id)
        clip_name = fix(clip_tree.get("m_Name", ""))
        writes = list(_animation_clip_constant_writes(clip_tree, tos, resource_attribute_maps))
        object_cache[clip_id] = []
        if include_stable_streamed:
            for evidence in _animation_clip_stable_material_pointer(clip_tree):
                material_id = int(evidence["material_path_id"])
                material = objects.get(material_id)
                if material is not None and material.type.name == "Material":
                    object_cache[clip_id].append(dict(evidence, clip_index=clip_id,
                        clip_path_id=str(path_id)))
        if include_stable_streamed:
            writes.extend(_animation_clip_stable_streamed_writes(clip_tree, tos))
        if activation_attribute_only:
            writes = [
                write for write in writes
                if int(write.get("attribute_hash", -1)) & 0xFFFFFFFF
                in activation_attribute_hashes
            ]
        for write in writes:
            item = dict(write)
            item.update({
                "clip_index": clip_id,
                "clip_path_id": str(path_id),
                "clip_name": clip_name,
            })
            item.setdefault("source", "animation_constant_clip")
            result.append(item)
        cache[clip_id] = result
        return result

    read.object_cache = object_cache
    return read


def _controller_condition_hashes(tree):
    """Collect serialized Animator condition EventIDs without name guessing."""
    result = set()
    controller = tree.get("m_Controller", {}) if isinstance(tree, dict) else {}
    if not isinstance(controller, dict):
        return result
    for raw_machine in controller.get("m_StateMachineArray", []) or []:
        machine = unwrap(raw_machine)
        if not isinstance(machine, dict):
            continue
        transition_groups = [machine.get("m_AnyStateTransitionConstantArray", [])]
        for raw_state in machine.get("m_StateConstantArray", []) or []:
            state = unwrap(raw_state)
            if isinstance(state, dict):
                transition_groups.append(
                    state.get("m_TransitionConstantArray", []) or [])
        for transitions in transition_groups:
            for raw_transition in transitions or []:
                transition = unwrap(raw_transition)
                if not isinstance(transition, dict):
                    continue
                for raw_condition in transition.get(
                        "m_ConditionConstantArray", []) or []:
                    condition = unwrap(raw_condition)
                    if not isinstance(condition, dict):
                        continue
                    event_id = _strict_int(condition.get("m_EventID"))
                    # EventID 0 is the serialized "no parameter" sentinel.
                    # Searching for its little-endian byte form (four zeroes)
                    # would match almost every AnimationClip and defeat the
                    # raw-data prefilter before expensive TypeTree reads.
                    if event_id is not None and event_id != 0:
                        result.add(event_id & 0xFFFFFFFF)
    return result


def _controller_tos_hashes_for_names(tree, names):
    wanted = {fix(name) for name in (names or []) if fix(name)}
    result = set()
    if not isinstance(tree, dict) or not wanted:
        return result
    for row in tree.get("m_TOS", []) or []:
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            continue
        raw_key, raw_value = row
        if fix(raw_value) not in wanted:
            continue
        key = _strict_int(raw_key)
        if key is not None:
            result.add(key & 0xFFFFFFFF)
    return result


def _bool_condition_polarity(condition, parameter):
    """Return +1/-1 for an explicit boolean true/false guard, else zero."""
    if not isinstance(condition, dict) or condition.get("parameter") != parameter:
        return 0
    mode = _strict_int(condition.get("mode"))
    try:
        threshold = float(condition.get("threshold", 0.0))
    except (TypeError, ValueError, OverflowError):
        return 0
    if not math.isfinite(threshold):
        return 0
    if mode == 1:
        return 1
    if mode == 2:
        return -1
    if mode == 3 and -0.01 <= threshold <= 1.01:
        return 1
    if mode == 4 and -0.01 <= threshold <= 1.01:
        return -1
    return 0


def _select_split_button_sentinel_effect_states(machines_by_index,
                                                  button_input_parameters):
    """Select only effect states proven to belong to a split-button lock.

    This is deliberately a structural gate, not a lock solver.  It recognizes
    an exclusive Bool-button dispatch that writes digits to one temporary
    parameter, a Copy-driver slot buffer with one common out-of-range sentinel,
    a comparator consuming all slots and writing one binary gate with a unique
    minority state, and finally a two-state consumer controlled in both
    directions by that gate.  Only the consumer's two states are returned for
    lazy AnimationClip inspection.
    """
    button_input_parameters = {
        fix(value) for value in (button_input_parameters or []) if fix(value)
    }
    if len(button_input_parameters) < 8:
        return {}

    def direct_digit_writes(state):
        result = []
        for write in state.get("parameter_writes", []) or []:
            if not isinstance(write, dict) or fix(write.get("source", "")):
                continue
            try:
                value = float(write.get("value"))
            except (TypeError, ValueError, OverflowError):
                continue
            rounded = int(round(value)) if math.isfinite(value) else -1
            if 0 <= rounded <= 9 and abs(value - rounded) <= 1e-7:
                name = fix(write.get("name", ""))
                if name:
                    result.append((name, rounded))
        return result

    dispatch_candidates = []
    for machine_index, machine in machines_by_index.items():
        states = machine.get("states", []) or []
        mappings = {}
        conflicts = set()
        for transition in machine.get("any_transitions", []) or []:
            positives = {
                parameter
                for parameter in button_input_parameters
                if any(_bool_condition_polarity(condition, parameter) == 1
                       for condition in transition.get("conditions", []) or [])
            }
            if len(positives) != 1:
                continue
            destination = _strict_int(transition.get("destination"))
            if destination is None or not (0 <= destination < len(states)):
                continue
            button = next(iter(positives))
            for temporary, digit in direct_digit_writes(states[destination]):
                old = mappings.get((temporary, button))
                if old is not None and old != digit:
                    conflicts.add((temporary, button))
                else:
                    mappings[(temporary, button)] = digit
        temporaries = {
            temporary for temporary, _button in mappings
            if (temporary, _button) not in conflicts
        }
        for temporary in temporaries:
            mapping = {
                button: digit
                for (candidate, button), digit in mappings.items()
                if candidate == temporary and (candidate, button) not in conflicts
            }
            if len(mapping) >= 8 and len(set(mapping.values())) >= 8:
                dispatch_candidates.append((machine_index, temporary, mapping))

    selected = {}
    for _dispatch_machine, temporary, _mapping in dispatch_candidates:
        copied_slots = set()
        for machine in machines_by_index.values():
            for state in machine.get("states", []) or []:
                for write in state.get("parameter_writes", []) or []:
                    if (isinstance(write, dict) and
                            _strict_int(write.get("type")) == 3 and
                            fix(write.get("source", "")) == temporary):
                        name = fix(write.get("name", ""))
                        if name and name != temporary:
                            copied_slots.add(name)
        if len(copied_slots) < 4:
            continue

        sentinel_found = False
        for machine in machines_by_index.values():
            for state in machine.get("states", []) or []:
                by_value = {}
                for write in state.get("parameter_writes", []) or []:
                    if not isinstance(write, dict) or fix(write.get("source", "")):
                        continue
                    name = fix(write.get("name", ""))
                    if name not in copied_slots:
                        continue
                    try:
                        value = float(write.get("value"))
                    except (TypeError, ValueError, OverflowError):
                        continue
                    rounded = int(round(value)) if math.isfinite(value) else 0
                    if abs(value - rounded) <= 1e-7 and not 0 <= rounded <= 9:
                        by_value.setdefault(rounded, set()).add(name)
                if any(names == copied_slots for names in by_value.values()):
                    sentinel_found = True
                    break
            if sentinel_found:
                break
        if not sentinel_found:
            continue

        for comparator_index, comparator in machines_by_index.items():
            condition_parameters = {
                fix(condition.get("parameter", ""))
                for state in comparator.get("states", []) or []
                for transition in state.get("transitions", []) or []
                for condition in transition.get("conditions", []) or []
                if isinstance(condition, dict)
            }
            condition_parameters.update({
                fix(condition.get("parameter", ""))
                for transition in comparator.get("any_transitions", []) or []
                for condition in transition.get("conditions", []) or []
                if isinstance(condition, dict)
            })
            if not copied_slots.issubset(condition_parameters):
                continue
            binary_writers = {}
            for state_index, state in enumerate(comparator.get("states", []) or []):
                for write in state.get("parameter_writes", []) or []:
                    if not isinstance(write, dict) or fix(write.get("source", "")):
                        continue
                    name = fix(write.get("name", ""))
                    if not name or name in copied_slots or name == temporary:
                        continue
                    try:
                        value = float(write.get("value"))
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if abs(value) <= 1e-7:
                        binary_writers.setdefault(name, {}).setdefault(0, set()).add(state_index)
                    elif abs(value - 1.0) <= 1e-7:
                        binary_writers.setdefault(name, {}).setdefault(1, set()).add(state_index)
            for gate, polarities in binary_writers.items():
                if set(polarities) != {0, 1}:
                    continue
                counts = sorted(len(states) for states in polarities.values())
                if counts[0] != 1 or counts[1] < 2:
                    continue
                for consumer_index, consumer in machines_by_index.items():
                    if consumer_index == comparator_index:
                        continue
                    consumer_states = consumer.get("states", []) or []
                    if len(consumer_states) != 2:
                        continue
                    cross_polarities = set()
                    for source_index, state in enumerate(consumer_states):
                        for transition in state.get("transitions", []) or []:
                            destination = _strict_int(transition.get("destination"))
                            if destination not in (0, 1) or destination == source_index:
                                continue
                            values = {
                                _bool_condition_polarity(condition, gate)
                                for condition in transition.get("conditions", []) or []
                            }
                            cross_polarities.update(value for value in values if value)
                    if cross_polarities == {-1, 1}:
                        selected.setdefault(consumer_index, set()).update((0, 1))
    return selected


def _select_compound_restriction_effect_states(machines_by_index):
    """Select two-state restriction consumers fed by one compound latch.

    Selection is based only on cross-machine write/read topology and condition
    modes.  It deliberately does not decide whether the effects are a lock;
    the native core performs that stricter proof after exact target binding.
    """
    writer_sites = {}
    for producer_index, producer in machines_by_index.items():
        for state_index, state in enumerate(producer.get("states", [])):
            for write in state.get("parameter_writes", []):
                if write.get("type") == 0 and write.get("value") in (0, 1):
                    writer_sites.setdefault(write.get("name"), []).append(
                        (producer_index, state_index, write.get("value")))
    selected = {}
    for consumer_index, consumer in machines_by_index.items():
        states = consumer.get("states", [])
        default = consumer.get("default_state")
        if (len(states) != 2 or consumer.get("any_transitions") or
                default not in (0, 1)):
            continue
        locked = states[default]
        if len(locked.get("transitions", [])) != 1:
            continue
        transition = locked["transitions"][0]
        terminal = transition.get("destination")
        conditions = transition.get("conditions", [])
        if (terminal not in (0, 1) or terminal == default or
                states[terminal].get("transitions") or len(conditions) != 1 or
                conditions[0].get("mode") not in (1, 2)):
            continue
        latch = conditions[0].get("parameter")
        sites = writer_sites.get(latch, [])
        if len(sites) != 1:
            continue
        producer_index, success_state, success_value = sites[0]
        wanted = 1 if conditions[0]["mode"] == 1 else 0
        producer = machines_by_index.get(producer_index, {})
        producer_states = producer.get("states", [])
        producer_default = producer.get("default_state")
        if (success_value != wanted or producer_index == consumer_index or
                producer.get("any_transitions") or
                not isinstance(producer_default, int) or
                not 0 <= producer_default < len(producer_states) or
                not 0 <= success_state < len(producer_states) or
                producer_states[success_state].get("transitions")):
            continue
        gates = [t for t in producer_states[producer_default].get("transitions", [])
                 if t.get("destination") == success_state]
        if len(gates) != 1 or not 3 <= len(gates[0].get("conditions", [])) <= 8:
            continue
        selected.setdefault(consumer_index, set()).update((default, terminal))
    return selected


def _select_guarded_numeric_effect_states(machines_by_index):
    """Select states for a shared-bool-gated numeric chain effect.

    Some generated lock families do not use a compact two-state consumer.
    Instead, one state machine contains a branched sequence of mode-6
    (discrete/equality) transitions.  Every digit edge carries the same
    boolean condition and the accepted path ends in a no-outgoing-edge state
    that writes the visible effect.  The final edge may contain only the
    shared boolean gate (the digit was accepted by the preceding edge).

    This is intentionally an extraction hint only.  It does not classify a
    lock, infer a password, or authorize a rewrite.  The native analyser must
    prove the complete path and bind the resulting effect to the runtime
    target.  All checks are structural and bounded so ordinary large FX
    machines cannot trigger an unbounded path walk.
    """
    selected = {}
    max_states = 512
    max_path_states = 64
    min_numeric_edges = 4
    min_distinct_values = 3

    def condition_rows(edge):
        rows = []
        for condition in edge.get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue
            parameter = fix(condition.get("parameter", ""))
            mode = _strict_int(condition.get("mode"))
            try:
                threshold = float(condition.get("threshold", 0.0))
            except (TypeError, ValueError, OverflowError):
                continue
            if parameter and mode is not None and math.isfinite(threshold):
                rows.append((parameter, mode, threshold))
        return rows

    def terminal_has_effect(state):
        # ParameterDriver writes are the cheap, stable effect signal available
        # in the parsed representation.  Keep animation evidence as a valid
        # fallback for callers that have already populated it (for example a
        # targeted deep pass); do not treat a state name as evidence.
        return bool(state.get("parameter_writes") or
                    state.get("animation_constant_writes") or
                    state.get("manual_activation_writes"))

    for machine_index, machine in machines_by_index.items():
        states = machine.get("states", []) or []
        default = machine.get("default_state")
        if (machine.get("any_transitions") or
                not isinstance(default, int) or default < 0 or
                default >= len(states) or len(states) < min_numeric_edges + 1 or
                len(states) > max_states):
            continue

        # Index edges once.  An edge is eligible for a candidate only when it
        # has exactly one numeric equality condition and exactly one Boolean
        # condition; extra conditions are deliberately left to native proof.
        edges = []
        for source, state in enumerate(states):
            for edge in state.get("transitions", []) or []:
                destination = _strict_int(edge.get("destination"))
                if (destination is None or destination < 0 or
                        destination >= len(states) or destination == source):
                    continue
                rows = condition_rows(edge)
                numeric = [row for row in rows if row[1] == 6]
                booleans = [row for row in rows if row[1] in (1, 2)]
                edges.append((source, destination, rows, numeric, booleans))

        # Group candidate digit edges by the numeric input and common Boolean
        # gate.  Requiring at least three repeated gate uses prevents a normal
        # isolated numeric toggle from being selected as an effect machine.
        grouped = {}
        for source, destination, rows, numeric, booleans in edges:
            if len(numeric) != 1 or len(booleans) != 1:
                continue
            numeric_parameter, _numeric_mode, numeric_value = numeric[0]
            gate_parameter, gate_mode, gate_value = booleans[0]
            if numeric_parameter == gate_parameter:
                continue
            key = (numeric_parameter, gate_parameter, gate_mode,
                   gate_value)
            grouped.setdefault(key, []).append(
                (source, destination, numeric_value))

        for grouped_key, numeric_edges in grouped.items():
            (numeric_parameter, gate_parameter, gate_mode,
             gate_value) = grouped_key
            if len(numeric_edges) < min_numeric_edges:
                continue
            if len({value for _source, _dest, value in numeric_edges}) < min_distinct_values:
                continue

            # Include gate-only edges so an accepted digit can hand off to a
            # terminal state on the next Animator evaluation tick.
            adjacency = {}
            for source, destination, value in numeric_edges:
                adjacency.setdefault(source, []).append(
                    (destination, True, value))
            for source, destination, rows, numeric, booleans in edges:
                if numeric or len(booleans) != 1:
                    continue
                parameter, mode, threshold = booleans[0]
                if (parameter == gate_parameter and mode == gate_mode and
                        threshold == gate_value):
                    adjacency.setdefault(source, []).append(
                        (destination, False, None))

            # Bounded DFS from the machine default.  Keep one path per state
            # and numeric depth; cycles and generated dead branches are
            # ignored without exploding the extractor.
            stack = [(default, 0, frozenset((default,)), (default,), ())]
            terminals = []
            seen = set()
            while stack and len(seen) <= 4096:
                state_index, numeric_count, visited, path, values = stack.pop()
                key = (state_index, numeric_count, tuple(sorted(visited)))
                if key in seen:
                    continue
                seen.add(key)
                outgoing = adjacency.get(state_index, [])
                if (not states[state_index].get("transitions") and
                        numeric_count >= min_numeric_edges and
                        len(set(values)) >= min_distinct_values and
                        terminal_has_effect(states[state_index])):
                    terminals.append((state_index, path, values))
                    continue
                if len(path) >= max_path_states:
                    continue
                for destination, consumes_digit, value in outgoing:
                    if destination in visited:
                        continue
                    next_values = values + ((value,) if consumes_digit else ())
                    stack.append((
                        destination,
                        numeric_count + (1 if consumes_digit else 0),
                        visited | {destination},
                        path + (destination,),
                        next_values,
                    ))

            if not terminals:
                continue
            # A machine can contain several wrong/dead terminal branches.  A
            # structural hint remains useful only while its selected footprint
            # stays bounded; native analysis will distinguish the real effect.
            footprint = set()
            for _terminal, path, _values in terminals[:16]:
                footprint.update(path)
            if not footprint or len(footprint) > max_path_states:
                continue
            selected.setdefault(machine_index, set()).update(footprint)
            break
    return selected


def _float32_ulp_distance(left, right):
    """Return an ordered IEEE-754 single-precision distance, or ``None``.

    Animator float thresholds are serialized as binary32 values even when the
    JSON adapter exposes them as Python ``float`` objects.  Comparing the
    encoded values prevents a normal-looking decimal difference from being
    mistaken for a narrow interval after a round-trip through JSON.
    """
    try:
        left_bits = struct.unpack("<I", struct.pack("<f", float(left)))[0]
        right_bits = struct.unpack("<I", struct.pack("<f", float(right)))[0]
    except (TypeError, ValueError, OverflowError, struct.error):
        return None
    if left_bits & 0x80000000:
        left_bits = 0x80000000 - (left_bits & 0x7fffffff)
    if right_bits & 0x80000000:
        right_bits = 0x80000000 - (right_bits & 0x7fffffff)
    return abs(int(left_bits) - int(right_bits))


def _select_float_range_gate_effect_states(machines_by_index):
    """Select effect states for a structural float-interval gate family.

    This is an extraction hint only.  It identifies a three-state producer
    whose success edge contains the same float parameter in GT/LT modes, a
    very narrow binary32 interval, and a Boolean latch condition.  The
    producer writes a binary gate consumed by one or more effect machines in
    both comparison polarities.  No model/author/state/parameter name is
    trusted and no lock or rewrite decision is made here; the native core must
    repeat the proof against the selected animation evidence.
    """
    def condition_groups(transition):
        groups = {}
        for condition in transition.get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue
            parameter = fix(condition.get("parameter", ""))
            mode = _strict_int(condition.get("mode"))
            try:
                threshold = float(condition.get("threshold", 0.0))
            except (TypeError, ValueError, OverflowError):
                continue
            if not parameter or mode not in (1, 2, 3, 4) or not math.isfinite(threshold):
                continue
            groups.setdefault(parameter, []).append((mode, threshold))
        return groups

    def narrow_interval(low, high):
        if not (math.isfinite(low) and math.isfinite(high) and high > low):
            return False
        width = high - low
        scale = max(abs(low), abs(high), 1.0)
        # Keep the test bounded in decimal space as well as binary32 space.
        # A very small absolute width covers low/medium magnitudes, while the
        # relative bound covers large finite values whose adjacent binary32
        # encodings are naturally farther apart in decimal notation.
        if width >= 1e-3 and width / scale >= 1e-6:
            return False
        distance = _float32_ulp_distance(low, high)
        return distance is not None and distance <= 256

    def binary_write_value(write):
        """Return a strict finite 0/1 constant write, otherwise ``None``."""
        if (not isinstance(write, dict) or fix(write.get("source", "")) or
                _strict_int(write.get("type")) != 0):
            return None
        try:
            value = float(write.get("value"))
        except (TypeError, ValueError, OverflowError):
            return None
        return value if math.isfinite(value) and value in (0.0, 1.0) else None

    producers = []
    for producer_index, machine in machines_by_index.items():
        states = machine.get("states", []) or []
        default = machine.get("default_state")
        if (len(states) != 3 or machine.get("any_transitions") or
                not isinstance(default, int) or not 0 <= default < 3):
            continue
        # Find a non-default state with a single success edge carrying the
        # narrow interval and a Boolean latch, then verify the complementary
        # out-of-range relock edges from the success state.
        for locked_index, locked in enumerate(states):
            if locked_index == default:
                continue
            for success_edge in locked.get("transitions", []) or []:
                success = _strict_int(success_edge.get("destination"))
                if success is None or success == locked_index or not 0 <= success < 3:
                    continue
                groups = condition_groups(success_edge)
                interval = None
                float_parameter = ""
                for parameter, values in groups.items():
                    modes = {mode for mode, _ in values}
                    if 3 not in modes or 4 not in modes:
                        continue
                    low = next((value for mode, value in values if mode == 3), None)
                    high = next((value for mode, value in values if mode == 4), None)
                    if low is None or high is None or not narrow_interval(low, high):
                        continue
                    interval = (low, high)
                    float_parameter = parameter
                    break
                if interval is None or not float_parameter:
                    continue
                bool_conditions = [
                    (parameter, mode, threshold)
                    for parameter, values in groups.items()
                    for mode, threshold in values
                    if parameter != float_parameter and mode in (1, 2)
                ]
                if not bool_conditions:
                    continue
                low, high = interval
                relock_bounds = set()
                relock_bool = set()
                for edge in states[success].get("transitions", []) or []:
                    edge_groups = condition_groups(edge)
                    for parameter, values in edge_groups.items():
                        if parameter == float_parameter:
                            for mode, value in values:
                                if mode not in (3, 4):
                                    continue
                                expected = high if mode == 3 else low
                                if _float32_ulp_distance(value, expected) == 0:
                                    relock_bounds.add(mode)
                        elif any(mode in (1, 2) for mode, _ in values):
                            relock_bool.update((parameter, mode) for mode, _ in values)
                if relock_bounds != {3, 4}:
                    continue
                # At least one latch used on the success edge must have the
                # opposite polarity on a relock edge.  Unrelated Boolean
                # conditions elsewhere in the state machine are not enough.
                if not any((parameter, 1 if mode == 2 else 2) in relock_bool
                           for parameter, mode, _ in bool_conditions):
                    continue
                # The producer must write one binary latch in the two states;
                # this is what ties the interval comparison to visible effects.
                writes_locked = [w for w in locked.get("parameter_writes", []) or []
                                 if binary_write_value(w) is not None]
                writes_success = [w for w in states[success].get("parameter_writes", []) or []
                                  if binary_write_value(w) is not None]
                gate_candidates = {
                    fix(a.get("name", "")): (a, b)
                    for a in writes_locked for b in writes_success
                    if fix(a.get("name", "")) and fix(a.get("name", "")) == fix(b.get("name", ""))
                    and binary_write_value(a) != binary_write_value(b)
                }
                if len(gate_candidates) != 1:
                    continue
                gate_parameter, (locked_write, success_write) = next(iter(gate_candidates.items()))
                # Require a default->locked environment edge.  The condition
                # name is intentionally not used; only a single bool-style
                # mode and the three-state topology are trusted here.
                entry_ok = any(
                    _strict_int(edge.get("destination")) == locked_index and
                    len(edge.get("conditions", []) or []) == 1 and
                    _strict_int((edge.get("conditions", []) or [])[0].get("mode")) == 1
                    for edge in states[default].get("transitions", []) or []
                )
                if not entry_ok:
                    continue
                producers.append({
                    "producer_index": producer_index,
                    "locked_index": locked_index,
                    "success_index": success,
                    "float_parameter": float_parameter,
                    "low": low,
                    "high": high,
                    "gate_parameter": gate_parameter,
                    "bool_parameters": sorted({item[0] for item in bool_conditions}),
                })

    selected = {}
    for producer in producers:
        gate = producer["gate_parameter"]
        for consumer_index, consumer in machines_by_index.items():
            if consumer_index == producer["producer_index"]:
                continue
            states = consumer.get("states", []) or []
            touched = set()
            polarities = set()
            for state_index, state in enumerate(states):
                for edge in state.get("transitions", []) or []:
                    destination = _strict_int(edge.get("destination"))
                    for condition in edge.get("conditions", []) or []:
                        if (fix(condition.get("parameter", "")) != gate or
                                _strict_int(condition.get("mode")) not in (3, 4)):
                            continue
                        polarities.add(_strict_int(condition.get("mode")))
                        touched.add(state_index)
                        if destination is not None and 0 <= destination < len(states):
                            touched.add(destination)
            if polarities == {3, 4} and len(touched) >= 2:
                selected.setdefault(consumer_index, set()).update(touched)
    return selected


def controller_json(obj, tree, scripts, include_animation_constant_writes=False,
                    activation_path_hashes=None,
                    parameter_attribute_hashes=None,
                    numeric_input_parameters=None,
                    parameter_hash_names=None,
                    split_button_parameters=None,
                    deep_machine_indices=None,
                    allow_local_effect_selection=True,
                    resource_attribute_maps=None):
    tos = {key: fix(value) for key, value in tree.get("m_TOS", []) or []}
    parameter_writes = _state_parameter_write_map(obj, tree, scripts)
    runtime_behaviours, behaviour_diagnostics = _state_runtime_behaviour_map(
        obj, tree, scripts)
    # State-machine parameter drivers are another independent name source. In
    # generated VRCFury controllers these names are often present in the
    # driver object but absent from m_TOS, while their CRC32 IDs still appear
    # in transition/BlendTree constants.
    driver_names = set()
    for writes in parameter_writes.values():
        for write in writes or []:
            if isinstance(write, dict):
                name = fix(write.get("name", ""))
                if name:
                    driver_names.add(name)
    # Generated controllers (notably VRCFury's Parameter Compressor) can
    # omit the original menu parameter names from m_TOS while retaining their
    # hashed IDs in m_Values/m_EventID.  Rehydrate only names that are
    # independently present in the avatar's expression/menu data, and never
    # overwrite an explicit m_TOS entry or a hash collision.
    for name in set(parameter_hash_names or []) | driver_names:
        name = fix(name)
        if not name:
            continue
        event_id = unity_animator_string_to_hash(name)
        existing = tos.get(event_id)
        if existing is None:
            tos[event_id] = name
        elif fix(existing) != name:
            # A collision is ambiguous; retain the serialized mapping and do
            # not guess which input the generated controller intended.
            continue
    controller = tree.get("m_Controller", {}) or {}
    raw_machine_records = controller.get("m_StateMachineArray", []) or []
    effective_deep_machine_indices = None
    if deep_machine_indices is not None:
        if not isinstance(deep_machine_indices, (list, tuple, set, frozenset)):
            raise ValueError("deep_machine_indices_invalid")
        if any(isinstance(index, bool) or not isinstance(index, int) or
               index < 0 or index >= len(raw_machine_records)
               for index in deep_machine_indices):
            raise ValueError("deep_machine_index_out_of_range")
        # The normalized machine array uses serialized order. A skipped raw
        # record would shift that order, so never publish coverage for it.
        if any(not isinstance(unwrap(machine), dict) for machine in raw_machine_records):
            raise ValueError("deep_machine_layout_incomplete")
        effective_deep_machine_indices = set(deep_machine_indices)
    if effective_deep_machine_indices is not None:
        written_names = {
            fix(write.get("name", ""))
            for (machine_index, _), writes in parameter_writes.items()
            if machine_index in effective_deep_machine_indices
            for write in writes or []
            if isinstance(write, dict) and fix(write.get("name", ""))
        }
        raw_machines = controller.get("m_StateMachineArray", []) or []
        for machine_index, raw_machine in enumerate(raw_machines):
            machine = unwrap(raw_machine)
            if not isinstance(machine, dict):
                continue
            if any(
                read.get("parameter") in written_names
                for raw_state in machine.get("m_StateConstantArray", []) or []
                for read in _state_blend_parameter_reads(unwrap(raw_state), tos)
            ):
                effective_deep_machine_indices.add(machine_index)
    numeric_input_parameters = set(numeric_input_parameters or [])
    contact_clip_writes = None
    parameter_clip_writes = None
    fallback_clip_writes = None
    if include_animation_constant_writes:
        if activation_path_hashes is not None:
            contact_clip_writes = _controller_clip_constant_reader(
                obj, tree, tos, activation_path_hashes, None,
                resource_attribute_maps=resource_attribute_maps)
        if parameter_attribute_hashes is not None:
            parameter_clip_writes = _controller_clip_constant_reader(
                obj, tree, tos, None, parameter_attribute_hashes,
                resource_attribute_maps=resource_attribute_maps)
        if contact_clip_writes is None and parameter_clip_writes is None:
            # An explicit server deep request asks for the serialized effects
            # of these machines, regardless of whether Unity stored a stable
            # activation curve in ConstantClip or StreamedClip. Remote clients
            # do not run family selectors, so relying on the local selector's
            # streamed reader silently discarded randomized-network effects.
            # The streamed decoder still rejects varying/non-Boolean curves;
            # this records facts only and never authorizes a restore plan.
            fallback_clip_writes = _controller_clip_constant_reader(
                obj, tree, tos, None, None,
                effective_deep_machine_indices is not None,
                resource_attribute_maps=resource_attribute_maps)
    machines = []
    machines_by_index = {}
    completed_deep_machine_indices = set()
    for machine_index, raw_machine in enumerate(
            controller.get("m_StateMachineArray", []) or []):
        machine = unwrap(raw_machine)
        if not isinstance(machine, dict):
            continue
        states = []
        raw_state_records = machine.get("m_StateConstantArray", []) or []
        selected_full_deep = (fallback_clip_writes is not None and
            effective_deep_machine_indices is not None and
            machine_index in effective_deep_machine_indices)
        if selected_full_deep and (not isinstance(raw_state_records, list) or
                any(not isinstance(unwrap(state), dict) for state in raw_state_records)):
            raise ValueError("deep_state_layout_incomplete")
        raw_states = [unwrap(item) for item in raw_state_records]
        selectors = _selector_states_json(machine, tos, len(raw_states))
        state_index_by_id = {}
        for index, raw_state in enumerate(raw_states):
            if not isinstance(raw_state, dict):
                continue
            state_id = _strict_int(raw_state.get("m_FullPathID"))
            if state_id is not None and state_id not in state_index_by_id:
                state_index_by_id[state_id] = index
        parsed_transitions_by_state = []
        numeric_clip_state_indexes = set()
        for source_index, state in enumerate(raw_states):
            transitions = []
            if isinstance(state, dict):
                for raw_transition in state.get(
                        "m_TransitionConstantArray", []) or []:
                    parsed = transition_json(
                        raw_transition, tos, state_index_by_id, len(raw_states), len(selectors))
                    if parsed is not None:
                        transitions.append(parsed)
            parsed_transitions_by_state.append(transitions)
            for transition in transitions:
                if any(condition.get("parameter") in numeric_input_parameters
                       for condition in transition.get("conditions", []) or []):
                    # A transition condition selects its destination state;
                    # the destination's Motion owns the clip that runs after
                    # the digit is accepted.  Retain the source as well for
                    # generated controllers that write on exit.
                    numeric_clip_state_indexes.add(source_index)
                    destination = transition.get("destination", -1)
                    if isinstance(destination, int) and 0 <= destination < len(raw_states):
                        numeric_clip_state_indexes.add(destination)
        any_transitions = []
        for raw_transition in machine.get(
                "m_AnyStateTransitionConstantArray", []) or []:
            parsed = transition_json(
                raw_transition, tos, state_index_by_id, len(raw_states), len(selectors))
            if parsed is None:
                continue
            any_transitions.append(parsed)
            if any(condition.get("parameter") in numeric_input_parameters
                   for condition in parsed.get("conditions", []) or []):
                destination = parsed.get("destination", -1)
                if isinstance(destination, int) and 0 <= destination < len(raw_states):
                    numeric_clip_state_indexes.add(destination)
        for index, state in enumerate(raw_states):
            if not isinstance(state, dict):
                state = {}
            transitions = parsed_transitions_by_state[index]
            state_id = _strict_int(state.get("m_FullPathID"))
            writes = parameter_writes.get((machine_index, state_id), []) \
                if state_id is not None else []
            animation_writes = []
            clip_ids = _state_clip_ids(state)
            blend_parameter_reads = _state_blend_parameter_reads(state, tos)
            if contact_clip_writes is not None:
                for clip_id in clip_ids:
                    animation_writes.extend(contact_clip_writes(clip_id))
            state_uses_numeric_input = index in numeric_clip_state_indexes
            if parameter_clip_writes is not None and state_uses_numeric_input:
                for clip_id in clip_ids:
                    animation_writes.extend(parameter_clip_writes(clip_id))
            if (fallback_clip_writes is not None and
                    (effective_deep_machine_indices is None or
                     machine_index in effective_deep_machine_indices)):
                for clip_id in clip_ids:
                    animation_writes.extend(fallback_clip_writes(clip_id))
            if len(animation_writes) > 1:
                unique_writes = []
                seen_writes = set()
                for item in animation_writes:
                    signature = (
                        item.get("clip_index"), item.get("attribute_hash"),
                        item.get("path_hash"), item.get("value"),
                        item.get("constant_index"))
                    if signature not in seen_writes:
                        seen_writes.add(signature)
                        unique_writes.append(item)
                animation_writes = unique_writes
            states.append({
                "name": state_name(state, index, tos),
                "transitions": transitions,
                "parameter_writes": writes,
                "runtime_behaviours": runtime_behaviours.get(
                    (machine_index, state_id), []) if state_id is not None else [],
                "animation_constant_writes": animation_writes,
                "blend_parameter_reads": blend_parameter_reads,
                "write_defaults": state.get("m_WriteDefaultValues") is True,
                "single_clip_motion": len(clip_ids) == 1 and not blend_parameter_reads and
                    sum(len(unwrap(t).get("m_NodeArray", [])) for t in
                        state.get("m_BlendTreeConstantArray", [])) == 1,
                "animation_object_writes": [w for clip_id in clip_ids
                    for w in (getattr(fallback_clip_writes, "object_cache", {}).get(clip_id, [])
                              if selected_full_deep else [])],
            })
        parsed_machine = {
            "default_state": int(machine.get("m_DefaultState", 0) or 0),
            "default_weight": _layer_default_weight(controller, machine_index),
            "states": states,
            "any_transitions": any_transitions,
            "selector_states": selectors,
        }
        machines.append(parsed_machine)
        machines_by_index[machine_index] = parsed_machine
        if selected_full_deep:
            # Reached only after every requested state's reader completed.
            # Empty clip/effect output is still a completed visit, never proof
            # of a harmless/complete effect or an authorization to rewrite.
            completed_deep_machine_indices.add(machine_index)

    # Production remote analysis deliberately does not run lock-family
    # selectors in the client adapter.  The server owns those rules.  A
    # targeted deep request can still ask for exact machine indices, but the
    # adapter must not independently expand that signed request by applying
    # local heuristics.
    effect_states = (_select_split_button_sentinel_effect_states(
        machines_by_index, split_button_parameters)
        if allow_local_effect_selection else {})
    # A compound avatar restriction can use one small producer machine to
    # latch a Boolean after several independent inputs, then a separate
    # two-state consumer to stop applying its default restriction clip.  The
    # parameter/state names are commonly randomized, so select this shape by
    # write/read topology and transition semantics only.
    if allow_local_effect_selection:
        for machine_index, states in _select_compound_restriction_effect_states(
            machines_by_index).items():
            effect_states.setdefault(machine_index, set()).update(states)
    # A narrow binary32 interval gate writes a binary latch that drives one or
    # more two/three-state effect machines.  Select only those effect states
    # for lazy clip inspection; native analysis performs the strict proof.
    if allow_local_effect_selection:
        for machine_index, states in _select_float_range_gate_effect_states(
            machines_by_index).items():
            effect_states.setdefault(machine_index, set()).update(states)
    # Some multi-stage locks keep the digit chain and its visible effect in
    # one machine.  Every digit edge shares one Boolean gate, and the accepted
    # path may finish with a gate-only edge before a terminal ParameterDriver
    # state.  Select that bounded footprint for lazy clip evidence; this is a
    # structural hint only and is not a native lock decision.
    if allow_local_effect_selection:
        for machine_index, states in _select_guarded_numeric_effect_states(
            machines_by_index).items():
            effect_states.setdefault(machine_index, set()).update(states)
    # Structural selection only. Random Bool generation plus a large pairwise
    # comparison network warrants reading terminal/relock effects; names and
    # exact generator state counts are irrelevant.
    if allow_local_effect_selection:
        for mi, machine in machines_by_index.items():
            states = machine.get("states", [])
            random_targets = {w.get("name") for s in states for w in s.get("parameter_writes", []) if w.get("type") == 2}
            compare_states = sum(any(len(t.get("conditions", [])) == 2 and
                all(x.get("mode") in (1, 2) and x.get("parameter") in random_targets for x in t["conditions"])
                for t in s.get("transitions", [])) for s in states)
            if len(random_targets) >= 8 and compare_states >= 8 and len(states) <= 4096:
                selected = {si for si,s in enumerate(states) if 1 <= len(s.get("parameter_writes", [])) <= 16 and
                    all(w.get("type") == 0 and w.get("value") in (0,1) for w in s["parameter_writes"])}
                if len(selected) <= 16:
                    effect_states.setdefault(mi, set()).update(selected)
    if effect_states:
        effect_clip_writes = _controller_clip_constant_reader(
            obj, tree, tos, None, None, True, True,
            resource_attribute_maps=resource_attribute_maps)
        raw_machines = controller.get("m_StateMachineArray", []) or []
        for machine_index, state_indexes in effect_states.items():
            if machine_index >= len(raw_machines):
                continue
            raw_machine = unwrap(raw_machines[machine_index])
            parsed_machine = machines_by_index.get(machine_index)
            if not isinstance(raw_machine, dict) or parsed_machine is None:
                continue
            raw_states = raw_machine.get("m_StateConstantArray", []) or []
            parsed_states = parsed_machine.get("states", []) or []
            for state_index in sorted(state_indexes):
                if state_index >= len(raw_states) or state_index >= len(parsed_states):
                    continue
                state = unwrap(raw_states[state_index])
                if not isinstance(state, dict):
                    continue
                animation_writes = parsed_states[state_index].setdefault(
                    "animation_constant_writes", [])
                for clip_id in _state_clip_ids(state):
                    animation_writes.extend(effect_clip_writes(clip_id))
                if len(animation_writes) > 1:
                    unique_writes = []
                    seen_writes = set()
                    for item in animation_writes:
                        signature = (
                            item.get("clip_index"), item.get("attribute_hash"),
                            item.get("path_hash"), item.get("value"),
                            item.get("constant_index"),
                            item.get("streamed_curve_index"))
                        if signature not in seen_writes:
                            seen_writes.add(signature)
                            unique_writes.append(item)
                    parsed_states[state_index]["animation_constant_writes"] = unique_writes
    # Data-only, bounded effect channel for non-numeric conjunction gates.
    # Keep separate from animation_constant_writes: discovering new display
    # evidence must not change existing password/rewrite decisions.
    if allow_local_effect_selection:
        manual_reader = None
        raw_machines = controller.get("m_StateMachineArray", []) or []
        for mi, machine in machines_by_index.items():
            states = machine.get("states", [])
            if not 3 <= len(states) <= 16 or machine.get("any_transitions"):
                continue
            selected = any(
                2 <= len(t.get("conditions", [])) <= 8 and
                all(x.get("mode") in (1, 2) for x in t["conditions"]) and
                0 <= t.get("destination", -1) < len(states) and
                not states[t["destination"]].get("transitions")
                for s in states for t in s.get("transitions", []))
            if not selected or mi >= len(raw_machines):
                continue
            if manual_reader is None:
                manual_reader = _controller_clip_constant_reader(
                    obj, tree, tos, None, None, True, True)
            raw_states = unwrap(raw_machines[mi]).get("m_StateConstantArray", [])
            for si, state in enumerate(states):
                if si >= len(raw_states):
                    continue
                state["manual_activation_writes"] = [
                    w for ci in _state_clip_ids(unwrap(raw_states[si]))
                    for w in manual_reader(ci)]
    return {"path_id": str(obj.path_id), "name": fix(tree.get("m_Name", "?")),
            "parameters": list(tos.values()),
            "parameter_defaults": _controller_parameter_defaults(controller, tos),
            "parameter_read_evidence": _controller_parameter_read_evidence(obj, tree, scripts, tos),
            "behaviour_diagnostics": behaviour_diagnostics,
            "machines": machines,
            "deep_scan_machine_indices": sorted(completed_deep_machine_indices)}, list(tos.values())


def ref_path_id(value):
    value = unwrap(value)
    if not isinstance(value, dict):
        return ""
    raw = value.get("m_PathID", value.get("path_id", 0))
    try:
        raw = int(raw)
    except Exception:
        return ""
    return str(raw) if raw else ""


def menu_json(obj, tree):
    controls = []
    objects = getattr(getattr(obj, "assets_file", None), "objects", {})
    objects = objects if isinstance(objects, dict) else {}
    for raw_control in tree.get("controls", []) or []:
        control = unwrap(raw_control)
        if not isinstance(control, dict):
            continue
        parameter = unwrap(control.get("parameter", {}))
        parameter = fix(parameter.get("name", "")) if isinstance(parameter, dict) else ""
        try:
            value = float(control.get("value", 0) or 0)
        except Exception:
            value = 0.0
        icon_reference = control.get("icon", {})
        icon_id = _local_pptr(icon_reference)
        icon_obj = objects.get(icon_id) if icon_id is not None else None
        icon_type = (
            icon_obj.type.name
            if icon_obj is not None and icon_obj.type.name in ("Texture2D", "Sprite")
            else "")
        controls.append({
            "name": fix(control.get("name", "")),
            "type": int(control.get("type", 0) or 0),
            "parameter": parameter,
            "value": value,
            "has_icon": bool(ref_path_id(icon_reference)),
            "icon_path_id": str(icon_id) if icon_type else "",
            "icon_type": icon_type,
            "submenu": ref_path_id(control.get("subMenu", {})),
            "preview_sub_parameters": [
                fix(unwrap(item).get("name", "")) if isinstance(unwrap(item), dict) else ""
                for item in (control.get("subParameters", []) or [])
            ],
            "sub_parameters": [
                fix(unwrap(item).get("name", ""))
                for item in (control.get("subParameters", []) or [])
                if isinstance(unwrap(item), dict) and unwrap(item).get("name")
            ],
        })
    return {"id": str(obj.path_id), "name": fix(tree.get("m_Name", "?")), "controls": controls}


def _active_menu_button_parameters(menus, active_root_menu_ids):
    """Collect Button parameters from the active menu closure without names."""
    menu_by_id = {
        str(menu.get("id", "")): menu
        for menu in (menus or [])
        if isinstance(menu, dict) and str(menu.get("id", ""))
    }
    roots = {
        str(value) for value in (active_root_menu_ids or [])
        if str(value) in menu_by_id
    }
    pending = list(roots if roots else menu_by_id)
    visited = set()
    parameters = set()
    while pending:
        menu_id = pending.pop()
        if menu_id in visited:
            continue
        visited.add(menu_id)
        menu = menu_by_id.get(menu_id)
        if not isinstance(menu, dict):
            continue
        for control in menu.get("controls", []) or []:
            if not isinstance(control, dict):
                continue
            submenu = str(control.get("submenu", ""))
            if submenu and submenu in menu_by_id and submenu not in visited:
                pending.append(submenu)
            if int(control.get("type", 0) or 0) != 101:
                continue
            parameter = fix(control.get("parameter", ""))
            if parameter:
                parameters.add(parameter)
    return parameters


def _read_named_mono_safe(obj, scripts, expected_scripts):
    """Read one explicitly allow-listed VRChat behaviour, including 1-4 byte
    protected headers.  Unlike the menu reader this does not use schema
    guessing: both the serialized script pointer and requested class name must
    agree before any fields are accepted.
    """
    script_name, header_shift = mono_script_location(obj, scripts)
    if script_name not in expected_scripts:
        return None, ""
    try:
        if header_shift:
            raw = obj.get_raw_data()
            tree = read_typetree_bytes(
                obj, obj._get_typetree_node(None),
                raw[header_shift:] + bytes(header_shift))
        else:
            tree = read_typetree_safe(obj)
    except Exception:
        return None, ""
    if not isinstance(tree, dict):
        return None, ""
    if scripts.get(_pointer_path_id(tree.get("m_Script")), "") != script_name:
        return None, ""
    return tree, script_name


def _active_avatar_references(environment, scripts):
    """Return validated, local references selected by VRCAvatarDescriptor.

    The bundle may contain copied or abandoned controllers/menus which are
    not used by the avatar at runtime.  Only a Descriptor with custom layers
    or custom expressions enabled can make a reference active.  Every PPtr is
    required to be local and to resolve to an object of the expected class;
    malformed/unsupported rows are ignored instead of being guessed.
    """
    active_fx_controller_ids = set()
    active_root_menu_ids = set()
    diagnostics = {
        "controller_binding_roots": [],
        "descriptor_count": 0,
        "custom_expressions_count": 0,
        "missing_expression_parameters_count": 0,
        "missing_expression_menu_count": 0,
        "custom_fx_count": 0,
        "missing_fx_controller_count": 0,
        "animation_hash_count": 0,
        "animation_hash_unique_count": 0,
    }
    animation_hash_names = set()
    try:
        objects_to_scan = environment.objects
    except Exception:
        return [], [], diagnostics
    for obj in objects_to_scan:
        try:
            if obj.type.name != "MonoBehaviour":
                continue
            tree, script_name = _read_named_mono_safe(
                obj, scripts, {"VRCAvatarDescriptor"})
            if tree is None or script_name != "VRCAvatarDescriptor":
                continue
            diagnostics["descriptor_count"] += 1
            for item in unwrap(tree.get("animationHashSet", [])) or []:
                item = unwrap(item)
                if not isinstance(item, dict):
                    continue
                name = fix(item.get("name", ""))
                if not name:
                    continue
                diagnostics["animation_hash_count"] += 1
                animation_hash_names.add(name)
            objects = getattr(getattr(obj, "assets_file", None), "objects", {})

            if bool(tree.get("customizeAnimationLayers", False)):
                for field in ("baseAnimationLayers", "specialAnimationLayers"):
                    layers = unwrap(tree.get(field, []))
                    if not isinstance(layers, list):
                        continue
                    for raw_layer in layers:
                        layer = unwrap(raw_layer)
                        if not isinstance(layer, dict) or layer.get("isDefault", True):
                            continue
                        cid = _local_pptr(layer.get("animatorController"))
                        gid = _local_pptr(tree.get("m_GameObject"))
                        if cid in objects and gid in objects and objects[cid].type.name == "AnimatorController" and objects[gid].type.name == "GameObject":
                            diagnostics["controller_binding_roots"].append({
                                "controller": str(cid), "root_game_object": str(gid),
                                "descriptor": str(obj.path_id)})

            # VRCAvatarDescriptor.AnimLayerType.FX == 5.  `isEnabled` is not a
            # runtime-selection flag in serialized descriptors produced by the
            # current SDK (valid custom layers commonly serialize it as zero).
            if bool(tree.get("customizeAnimationLayers", False)):
                layers = unwrap(tree.get("baseAnimationLayers", []))
                if isinstance(layers, list):
                    for raw_layer in layers:
                        layer = unwrap(raw_layer)
                        if not isinstance(layer, dict):
                            continue
                        if _strict_int(layer.get("type")) != 5:
                            continue
                        diagnostics["custom_fx_count"] += 1
                        controller_id = _local_pptr(layer.get("animatorController"))
                        controller_obj = objects.get(controller_id)
                        if (controller_id is not None and controller_obj is not None and
                                controller_obj.type.name == "AnimatorController"):
                            active_fx_controller_ids.add(str(controller_id))
                        else:
                            diagnostics["missing_fx_controller_count"] += 1

            if bool(tree.get("customExpressions", False)):
                diagnostics["custom_expressions_count"] += 1
                menu_id = _local_pptr(tree.get("expressionsMenu"))
                menu_obj = objects.get(menu_id)
                if (menu_id is not None and menu_obj is not None and
                        menu_obj.type.name == "MonoBehaviour" and
                        mono_script_name(menu_obj, scripts) == "VRCExpressionsMenu"):
                    active_root_menu_ids.add(str(menu_id))
                else:
                    diagnostics["missing_expression_menu_count"] += 1
                parameters_id = _local_pptr(tree.get("expressionParameters"))
                parameters_obj = objects.get(parameters_id)
                if not (parameters_id is not None and parameters_obj is not None and
                        parameters_obj.type.name == "MonoBehaviour" and
                        mono_script_name(parameters_obj, scripts) ==
                        "VRCExpressionParameters"):
                    diagnostics["missing_expression_parameters_count"] += 1
        except Exception:
            # Descriptor evidence is optional schema context.  Never turn an
            # unreadable pointer/object table into an active runtime guess.
            continue

    diagnostics["animation_hash_unique_count"] = len(animation_hash_names)
    binding_roots = diagnostics["controller_binding_roots"]
    descriptor_objects = {r["root_game_object"] for r in binding_roots}
    closure_complete = True
    for obj in environment.objects:
        if obj.type.name != "Animator":
            continue
        tree = read_typetree_safe(obj)
        if not isinstance(tree, dict):
            closure_complete = False
            continue
        gid = _local_pptr(tree.get("m_GameObject"))
        if str(gid) in descriptor_objects:
            continue
        cid = _local_pptr(tree.get("m_Controller"))
        if cid is None:
            continue
        objects = obj.assets_file.objects
        if cid not in objects or objects[cid].type.name != "AnimatorController":
            closure_complete = False
            continue
        binding_roots.append({"controller": str(cid), "root_game_object": str(gid), "animator": str(obj.path_id)})
    diagnostics["controller_selection_complete"] = closure_complete
    return (sorted(active_fx_controller_ids, key=int),
            sorted(active_root_menu_ids, key=int), diagnostics)


def _xyz(value):
    value = unwrap(value)
    if not isinstance(value, dict):
        return None
    try:
        result = [float(value.get(axis, 0.0)) for axis in ("x", "y", "z")]
    except (TypeError, ValueError, OverflowError):
        return None
    return result if all(math.isfinite(item) for item in result) else None


def _contact_game_object_info(obj, game_object_value):
    game_object_id = _pointer_path_id(game_object_value)
    objects = getattr(getattr(obj, "assets_file", None), "objects", {})
    game_object = objects.get(game_object_id)
    if game_object is None or game_object.type.name != "GameObject":
        return {}
    tree = read_typetree_safe(game_object)
    if not isinstance(tree, dict):
        return {}
    transform_id = 0
    transform_tree = None
    for raw_component in tree.get("m_Component", []) or []:
        component = unwrap(raw_component)
        if not isinstance(component, dict):
            continue
        candidate_id = _pointer_path_id(component.get("component"))
        candidate = objects.get(candidate_id)
        if candidate is None or candidate.type.name != "Transform":
            continue
        transform_id = candidate_id
        transform_tree = read_typetree_safe(candidate)
        break
    result = {
        "game_object": str(game_object_id),
        "game_object_name": fix(tree.get("m_Name", "")),
        "game_object_active": bool(tree.get("m_IsActive", False)),
    }
    if isinstance(transform_tree, dict):
        result.update({
            "transform": str(transform_id),
            "parent_transform": str(_pointer_path_id(transform_tree.get("m_Father"))),
            "local_position": _xyz(transform_tree.get("m_LocalPosition")),
            "local_scale": _xyz(transform_tree.get("m_LocalScale")),
        })
        # Animation binding paths are CRC32 hashes of a hierarchy path relative
        # to an Animator root.  Record every valid suffix of this Transform's
        # ancestry so a generated controller can be matched without depending
        # on concrete GameObject names or one avatar's PathIDs.
        names = []
        current_id = transform_id
        visited = set()
        for _ in range(64):
            if not current_id or current_id in visited:
                break
            visited.add(current_id)
            current = objects.get(current_id)
            if current is None or current.type.name != "Transform":
                break
            current_tree = read_typetree_safe(current)
            if not isinstance(current_tree, dict):
                break
            current_go_id = _pointer_path_id(current_tree.get("m_GameObject"))
            current_go = objects.get(current_go_id)
            current_name = ""
            if current_go is not None and current_go.type.name == "GameObject":
                current_go_tree = read_typetree_safe(current_go)
                if isinstance(current_go_tree, dict):
                    current_name = fix(current_go_tree.get("m_Name", ""))
            if current_name:
                names.append(current_name)
            current_id = _pointer_path_id(current_tree.get("m_Father"))
        root_to_leaf = list(reversed(names))
        paths = {
            "/".join(root_to_leaf[index:])
            for index in range(len(root_to_leaf))
            if root_to_leaf[index:]
        }
        result["hierarchy_path_hashes"] = sorted({
            zlib.crc32(path.encode("utf-8")) & 0xFFFFFFFF
            for path in paths if path
        })
    return result


def _build_exact_binding_index(objects, root_game_object, max_objects=50000):
    """Resolve local root-relative paths without dropping duplicates/collisions.

    This proves serialized targets, not whether a clip wins runtime blending.
    Any broken subtree makes the index incomplete; no unique claims then.
    """
    index = {}
    seen = set()
    stack = [(root_game_object, "", None)]
    complete = True
    while stack:
        gid, path, expected_parent = stack.pop()
        if gid in seen or len(seen) >= max_objects:
            complete = False
            continue
        seen.add(gid)
        go = objects.get(gid)
        if go is None or go.type.name != "GameObject":
            complete = False
            continue
        tree = read_typetree_safe(go)
        if not isinstance(tree, dict):
            complete = False
            continue
        components = []
        transforms = []
        for raw in tree.get("m_Component", []) or []:
            raw = unwrap(raw)
            cid = _local_pptr(raw.get("component")) if isinstance(raw, dict) else None
            obj = objects.get(cid)
            if obj is None:
                complete = False
                continue
            components.append((str(cid), int(obj.type)))
            if obj.type.name == "Transform":
                transforms.append(obj)
        if len(transforms) != 1:
            complete = False
            continue
        transform = transforms[0]
        t = read_typetree_safe(transform)
        if not isinstance(t, dict) or _local_pptr(t.get("m_GameObject")) != gid:
            complete = False
            continue
        if expected_parent is not None and _local_pptr(t.get("m_Father")) != expected_parent:
            complete = False
            continue
        index.setdefault(zlib.crc32(path.encode("utf-8")) & 0xFFFFFFFF, []).append({
            "game_object": str(gid), "path": path, "components": components,
            "game_object_active": bool(tree.get("m_IsActive", True))})
        for pointer in t.get("m_Children", []) or []:
            child = objects.get(_local_pptr(pointer))
            if child is None or child.type.name != "Transform":
                complete = False
                continue
            child_tree = read_typetree_safe(child)
            child_gid = _local_pptr(child_tree.get("m_GameObject")) if isinstance(child_tree, dict) else None
            child_go = objects.get(child_gid)
            child_go_tree = read_typetree_safe(child_go) if child_go is not None and child_go.type.name == "GameObject" else None
            if not isinstance(child_go_tree, dict) or not isinstance(child_go_tree.get("m_Name"), str) or not child_go_tree["m_Name"] or "/" in child_go_tree["m_Name"]:
                complete = False
                continue
            child_path = path + "/" + child_go_tree["m_Name"] if path else child_go_tree["m_Name"]
            stack.append((child_gid, child_path, transform.path_id))
    return {"complete": complete, "paths": index, "resource_objects": objects,
            "resource_curve_cache": {}}


def _resource_attribute_maps(objects):
    """Build collision-aware custom AnimationClip attribute maps.

    AjisaiFlow's generated clips use Unity custom binding types instead of
    ordinary TOS names: type 20 targets Mesh BlendShape nameHash and type 22
    targets tagged shader-property CRCs.  This function reads only names from
    the same serialized object graph and returns tuples for collisions; it
    never invents names from the package brand or from the expected lock.
    """
    result = {20: {}, 22: {}}
    if not isinstance(objects, dict):
        try:
            objects = {o.path_id: o for o in objects}
        except Exception:
            return result

    def add(kind, key, name):
        if type(key) is not int or not 0 <= key <= 0xFFFFFFFF or not name:
            return
        bucket = result[kind].setdefault(key, set())
        bucket.add(name)

    for obj in objects.values():
        kind = getattr(getattr(obj, "type", None), "name", "")
        if kind == "Mesh":
            tree = read_typetree_safe(obj)
            shapes = tree.get("m_Shapes", {}) if isinstance(tree, dict) else {}
            for channel in shapes.get("channels", []) if isinstance(shapes, dict) else []:
                if not isinstance(channel, dict):
                    continue
                name = fix(channel.get("name", ""))
                if not name:
                    continue
                value = _strict_int(channel.get("nameHash"))
                add(20, value if value is not None else zlib.crc32(name.encode("utf-8")) & 0xFFFFFFFF,
                    "blendShape." + name)
        elif kind == "Material":
            tree = read_typetree_safe(obj)
            saved = tree.get("m_SavedProperties", {}) if isinstance(tree, dict) else {}
            if not isinstance(saved, dict):
                continue
            names = []
            # 0x8 is the observed serialized Float-property tag. Do not assign
            # that tag to texture/vector/int records with different layouts.
            for field in ("m_Floats",):
                values = saved.get(field, [])
                if isinstance(values, list):
                    names.extend(item[0] for item in values
                                 if isinstance(item, (list, tuple)) and len(item) == 2
                                 and isinstance(item[0], str))
            for name in names:
                if name.startswith("_AR_"):
                    crc = zlib.crc32(name.encode("utf-8")) & 0x0FFFFFFF
                    add(22, 0x80000000 | crc, "material." + name)
    for kind in result:
        for key, values in list(result[kind].items()):
            result[kind][key] = tuple(sorted(values))
    return result


def _custom_resource_attribute_present(index, target_id, write):
    """Require the named custom curve on this renderer's actual resources."""
    kind = write.get("custom_type")
    if kind not in (20, 22):
        return True
    objects = index.get("resource_objects", {})
    cache = index.setdefault("resource_curve_cache", {})
    key = (str(target_id), kind)
    if key not in cache:
        names = set()
        try:
            renderer = objects.get(int(target_id))
            tree = read_typetree_safe(renderer) if renderer is not None else None
            if not isinstance(tree, dict):
                tree = {}
            if kind == 20:
                mesh = objects.get(_local_pptr(tree.get("m_Mesh")))
                if mesh is not None and mesh.type.name == "Mesh":
                    mt = read_typetree_safe(mesh)
                    for channel in mt.get("m_Shapes", {}).get("channels", []) if isinstance(mt, dict) else []:
                        if not isinstance(channel, dict):
                            continue
                        name = fix(channel.get("name", ""))
                        hashed = _strict_int(channel.get("nameHash"))
                        if name and hashed is not None:
                            names.add(("blendShape." + name, hashed))
            else:
                for pointer in tree.get("m_Materials", []) or []:
                    material = objects.get(_local_pptr(pointer))
                    if material is None or material.type.name != "Material":
                        continue
                    mt = read_typetree_safe(material)
                    saved = mt.get("m_SavedProperties", {}) if isinstance(mt, dict) else {}
                    for row in saved.get("m_Floats", []) if isinstance(saved, dict) else []:
                        if isinstance(row, (list, tuple)) and len(row) == 2 and isinstance(row[0], str):
                            name = row[0]
                            if name.startswith("_AR_"):
                                names.add(("material." + name,
                                    0x80000000 | (zlib.crc32(name.encode("utf-8")) & 0x0FFFFFFF)))
        except (ValueError, TypeError, AttributeError):
            names = set()
        cache[key] = names
    return (write.get("attribute"), write.get("attribute_hash")) in cache[key]


def _resolve_exact_binding(index, write):
    result = {"status": "unknown", "runtime_verified": False}
    if not index["complete"]:
        result["status"] = "incomplete_hierarchy"
        return result
    path_hash, type_id = write.get("path_hash"), write.get("type_id")
    if type(path_hash) is not int or not 0 <= path_hash <= 0xFFFFFFFF or type(type_id) is not int:
        return result
    paths = index["paths"].get(path_hash, [])
    if len(paths) != 1:
        result["status"] = "missing_path" if not paths else "ambiguous_path"
        return result
    target = paths[0]
    # GameObject m_IsActive is not a Component. MonoBehaviour type 114 alone
    # cannot select among multiple scripts on one object: retain ambiguity.
    candidates = [target["game_object"]] if type_id == 1 else [cid for cid, kind in target["components"] if kind == type_id]
    if len(candidates) != 1:
        result["status"] = "missing_component" if not candidates else "ambiguous_component"
        return result
    result.update(status="unique_serialized_target", path=target["path"],
                  game_object=target["game_object"], target_id=candidates[0], type_id=type_id)
    if not _custom_resource_attribute_present(index, candidates[0], write):
        result["status"] = "resource_attribute_unproven"
    if type_id == 1:
        result["serialized_active"] = target["game_object_active"]
    return result


def _contact_binding_metadata(contact):
    """Preserve candidate bindings without asserting an Animator-root match."""
    hashes = contact.get("hierarchy_path_hashes", []) or []
    return {
        "transform": contact.get("transform", ""),
        "parent_transform": contact.get("parent_transform", ""),
        "root_transform": contact.get("root_transform"),
        "local_scale": contact.get("local_scale"),
        "hierarchy_path_hashes": sorted({value for value in hashes
            if type(value) is int and 0 <= value <= 0xFFFFFFFF}),
        "binding_scope": "hierarchy_suffix_candidates_not_verified_animator_root",
    }


def contact_json(obj, tree, script_name):
    tags = []
    tag_decode_errors = 0
    for item in tree.get("collisionTags", []) or []:
        tag = fix(item)
        try:
            tag.encode("utf-8", "strict")
        except UnicodeEncodeError:
            # A truncated UTF-8 Contact tag is not evidence of a match. Keep
            # the component and receiver parameter (an external/unknown input)
            # but never replace/drop bytes to invent a matching tag. Native
            # records all receiver parameters even when no tags are proven.
            tag_decode_errors += 1
            continue
        if tag:
            tags.append(tag)
    root_pointer = unwrap(tree.get("rootTransform"))
    root_transform = None
    if isinstance(root_pointer, dict) and _strict_int(root_pointer.get("m_FileID")) == 0:
        root_transform = _strict_int(root_pointer.get("m_PathID"))
    row = {
        "path_id": str(obj.path_id),
        "root_transform": root_transform,
        "kind": "receiver" if script_name == "VRCContactReceiver" else "sender",
        "enabled": bool(tree.get("m_Enabled", False)),
        "local_only": bool(tree.get("localOnly", False)),
        "tags": tags,
        "shape_type": int(tree.get("shapeType", 0) or 0),
        "position": _xyz(tree.get("position")),
    }
    if tag_decode_errors:
        row["tag_decode_error_count"] = tag_decode_errors
    try:
        row["radius"] = float(tree.get("radius", 0.0) or 0.0)
    except (TypeError, ValueError, OverflowError):
        row["radius"] = 0.0
    if script_name == "VRCContactReceiver":
        row.update({
            "parameter": fix(tree.get("parameter", "")),
            "receiver_type": int(tree.get("receiverType", -1)),
            "allow_self": bool(tree.get("allowSelf", False)),
            "allow_others": bool(tree.get("allowOthers", False)),
        })
    row.update(_contact_game_object_info(obj, tree.get("m_GameObject")))
    return row


def _near_zero(values, epsilon=1e-6):
    return isinstance(values, list) and len(values) == 3 and all(
        abs(float(value)) <= epsilon for value in values)


def fixed_contact_gates(contacts):
    """Return only statically certain self-contact gates.  The sender must be
    a zero-offset child of the receiver (or vice versa), both components and
    GameObjects must be enabled, and a Constant receiver must explicitly allow
    self contacts.  Ambiguous spatial arrangements are ignored.
    """
    by_tag = {}
    for contact in contacts:
        for tag in contact.get("tags", []):
            by_tag.setdefault(tag, []).append(contact)
    result = []
    for tag, rows in by_tag.items():
        receivers = [row for row in rows if row.get("kind") == "receiver"]
        senders = [row for row in rows if row.get("kind") == "sender"]
        for receiver in receivers:
            if (not receiver.get("enabled") or
                    not receiver.get("game_object_active") or
                    not receiver.get("allow_self") or
                    receiver.get("receiver_type") != 0 or
                    not receiver.get("parameter") or
                    not _near_zero(receiver.get("position"))):
                continue
            for sender in senders:
                if (not sender.get("enabled") or
                        not sender.get("game_object_active") or
                        not _near_zero(sender.get("position")) or
                        not _near_zero(sender.get("local_position"))):
                    continue
                nested = (
                    sender.get("parent_transform") == receiver.get("transform") or
                    receiver.get("parent_transform") == sender.get("transform") or
                    sender.get("transform") == receiver.get("transform"))
                if not nested:
                    continue
                result.append({
                    "parameter": receiver["parameter"],
                    "tag": tag,
                    "receiver_path_id": receiver["path_id"],
                    "sender_path_id": sender["path_id"],
                    "receiver_game_object": receiver.get("game_object", ""),
                    "sender_game_object": sender.get("game_object", ""),
                    "forced_value": 1.0,
                    "evidence": "enabled_zero_offset_nested_self_contact",
                })
                break
    return result


def dynamic_contact_parameters(contact_gates, contacts, controllers):
    """Return Contact receiver parameters whose initially overlapping sender
    is explicitly animated both enabled and disabled by an active controller.

    A zero-offset nested sender is only a forced constant while it remains
    enabled.  Requiring both activation polarities on the exact hierarchy hash
    prevents an unrelated animation from weakening the fixed-gate proof.
    """
    by_path_id = {str(item.get("path_id", "")): item for item in contacts}
    dynamic = set()
    activation_hashes = {
        zlib.crc32(b"m_Enabled") & 0xFFFFFFFF,
        zlib.crc32(b"m_IsActive") & 0xFFFFFFFF,
    }
    for gate in contact_gates:
        sender = by_path_id.get(str(gate.get("sender_path_id", "")), {})
        path_hashes = {
            int(value) for value in sender.get("hierarchy_path_hashes", [])
            if isinstance(value, int)
        }
        if not path_hashes:
            continue
        values = set()
        for controller in controllers:
            for machine in controller.get("machines", []):
                for state in machine.get("states", []):
                    for write in state.get("animation_constant_writes", []):
                        if (write.get("attribute_hash") in activation_hashes and
                                write.get("path_hash") in path_hashes):
                            try:
                                values.add(1 if float(write.get("value", 0)) > 0.5 else 0)
                            except (TypeError, ValueError, OverflowError):
                                pass
        if values == {0, 1} and gate.get("parameter"):
            dynamic.add(fix(gate["parameter"]))
    return sorted(dynamic)


def is_md5_name(value):
    return len(value) == 32 and all(char in "0123456789abcdef" for char in value)


def has_unicode_obfuscation(value):
    for char in value:
        code = ord(char)
        if 0x200B <= code <= 0x200F or 0x202A <= code <= 0x202E or 0x2060 <= code <= 0x206F or 0x0300 <= code <= 0x036F or code == 0xFEFF:
            return True
    return False


def _empty_quadratic():
    return {"q": [[0.0] * 4 for _ in range(4)],
            "p": [0.0] * 4, "r": 0.0, "count": 0}


def _accumulate_quadratic(target, row, rhs, weight):
    for i in range(4):
        target["p"][i] += weight * row[i] * rhs
        for j in range(4):
            target["q"][i][j] += weight * row[i] * row[j]
    target["r"] += weight * rhs * rhs
    target["count"] += 1


def _vector3(value):
    try:
        return (float(value[0]), float(value[1]), float(value[2]))
    except Exception:
        return None


def _vector2(value):
    try:
        return (float(value[0]), float(value[1]))
    except Exception:
        return None


def _avacrypt_v1_uv_signature(uv6, uv7, vertex_count):
    if not uv6 or not uv7 or len(uv6) != vertex_count or len(uv7) != vertex_count:
        return None
    step = max(1, vertex_count // 4096)
    values = []
    for index in range(0, vertex_count, step):
        left = _vector2(uv6[index])
        right = _vector2(uv7[index])
        if left is None or right is None:
            continue
        values.extend((left[0], left[1], right[0], right[1]))
    if len(values) < 256 or not all(math.isfinite(value) for value in values):
        return None
    nonpositive = sum(value <= 1e-7 for value in values) / float(len(values))
    negative = sum(value < -1e-7 for value in values) / float(len(values))
    span = max(values) - min(values)
    # GTAvaCrypt V1 writes four independent Random.Range(min, 0) offsets into
    # Unity uv7/uv8 (TEXCOORD6/7).  This bounded sign signature avoids treating
    # ordinary lightmaps or radial-menu data as encrypted mesh evidence.
    if nonpositive < 0.98 or negative < 0.80 or span <= 1e-6:
        return None
    return {"nonpositive_ratio": nonpositive,
            "negative_ratio": negative, "span": span}


def _avacrypt_v1_mesh_probe(obj, deadline):
    if time.monotonic() >= deadline:
        return None
    try:
        from UnityPy.helpers.MeshHelper import MeshHandler
        mesh = obj.read()
        handler = MeshHandler(mesh)
        handler.process()
        vertices = handler.m_Vertices or []
        normals = handler.m_Normals or []
        uv6 = handler.m_UV6 or []
        uv7 = handler.m_UV7 or []
        vertex_count = len(vertices)
        if vertex_count < 64 or len(normals) != vertex_count:
            return None
        signature = _avacrypt_v1_uv_signature(uv6, uv7, vertex_count)
        if signature is None:
            return None
        submeshes = handler.get_triangles()
    except Exception:
        return None

    total_triangles = sum(len(items) for items in submeshes)
    if total_triangles < 64:
        return None
    triangle_step = max(1, total_triangles // 8000)
    train = _empty_quadratic()
    validation = _empty_quadratic()
    seen_edges = set()
    triangle_index = 0
    stop = False

    for triangles in submeshes:
        for triangle in triangles:
            if triangle_index % 256 == 0 and time.monotonic() >= deadline:
                stop = True
                break
            use_triangle = triangle_index % triangle_step == 0
            triangle_index += 1
            if not use_triangle or len(triangle) != 3:
                continue
            for left_index, right_index in ((triangle[0], triangle[1]),
                                            (triangle[1], triangle[2]),
                                            (triangle[2], triangle[0])):
                try:
                    left_index = int(left_index)
                    right_index = int(right_index)
                except Exception:
                    continue
                if left_index == right_index or left_index < 0 or right_index < 0 or \
                        left_index >= vertex_count or right_index >= vertex_count:
                    continue
                edge_id = (min(left_index, right_index), max(left_index, right_index))
                if edge_id in seen_edges:
                    continue
                seen_edges.add(edge_id)

                left_vertex = _vector3(vertices[left_index])
                right_vertex = _vector3(vertices[right_index])
                left_normal = _vector3(normals[left_index])
                right_normal = _vector3(normals[right_index])
                left_uv6 = _vector2(uv6[left_index])
                right_uv6 = _vector2(uv6[right_index])
                left_uv7 = _vector2(uv7[left_index])
                right_uv7 = _vector2(uv7[right_index])
                if None in (left_vertex, right_vertex, left_normal, right_normal,
                            left_uv6, right_uv6, left_uv7, right_uv7):
                    continue

                left_length = math.sqrt(sum(value * value for value in left_normal))
                right_length = math.sqrt(sum(value * value for value in right_normal))
                if left_length <= 1e-8 or right_length <= 1e-8:
                    continue
                ni = tuple(value / left_length for value in left_normal)
                nj = tuple(value / right_length for value in right_normal)
                normal_dot = sum(ni[i] * nj[i] for i in range(3))
                if normal_dot < 0.25:
                    continue
                normal_sum = tuple(ni[i] + nj[i] for i in range(3))
                normal_sum_length = math.sqrt(sum(value * value for value in normal_sum))
                if normal_sum_length <= 1e-8:
                    continue
                average_normal = tuple(value / normal_sum_length for value in normal_sum)
                edge = tuple(right_vertex[i] - left_vertex[i] for i in range(3))
                edge_length_sq = sum(value * value for value in edge)
                if edge_length_sq <= 1e-16:
                    continue
                rhs = sum(edge[i] * average_normal[i] for i in range(3))
                left_offsets = (left_uv6[0], left_uv6[1],
                                left_uv7[0], left_uv7[1])
                right_offsets = (right_uv6[0], right_uv6[1],
                                 right_uv7[0], right_uv7[1])
                row = []
                for component in range(4):
                    row.append(sum((nj[i] * right_offsets[component] -
                                    ni[i] * left_offsets[component]) *
                                   average_normal[i] for i in range(3)))
                if sum(value * value for value in row) <= 1e-18:
                    continue
                smooth_weight = (0.5 + 0.5 * min(1.0, normal_dot)) ** 4
                weight = min(1e8, smooth_weight / max(edge_length_sq, 1e-12))
                bucket = train if (((edge_id[0] * 73856093) ^
                                    (edge_id[1] * 19349663)) & 1) == 0 else validation
                if bucket["count"] < 6000:
                    _accumulate_quadratic(bucket, row, rhs, weight)
            if train["count"] >= 6000 and validation["count"] >= 6000:
                stop = True
                break
        if stop:
            break

    if train["count"] < 128 or validation["count"] < 128:
        return None
    return {
        "name": fix(getattr(mesh, "m_Name", "") or ("mesh_%s" % obj.path_id)),
        "path_id": str(obj.path_id),
        "vertex_count": vertex_count,
        "triangle_count": total_triangles,
        "uv_signature": signature,
        "train": train,
        "validation": validation,
    }


def _collect_avacrypt_v1_mesh_probes(environment, max_seconds=20.0):
    deadline = time.monotonic() + max_seconds
    objects = [obj for obj in environment.objects if obj.type.name == "Mesh"]
    # Body meshes tend to be among the larger serialized Mesh objects.  Probe
    # them first, then stop as soon as several independent summaries exist.
    objects.sort(key=lambda obj: int(getattr(obj, "byte_size", 0) or 0), reverse=True)
    probes = []
    for obj in objects[:12]:
        if time.monotonic() >= deadline or len(probes) >= 3:
            break
        probe = _avacrypt_v1_mesh_probe(obj, deadline)
        if probe is not None:
            probes.append(probe)
    return probes


def _collect_avacrypt_offset_mesh_signatures(environment, max_seconds=20.0):
    """Find GTAvaCrypt-style negative UV6/UV7 offsets without solving a key.

    Stock lilToon exposes _BitKey0..31 properties even when encryption is not
    compiled into the shader.  A real GTAvaCrypt V1/V2 mesh also carries four
    per-vertex offsets written to Unity uv7/uv8 (MeshHelper UV6/UV7).  This
    bounded geometry check is therefore the required second factor for a
    detached/external mesh-lock classification.
    """
    from UnityPy.helpers.MeshHelper import MeshHandler

    deadline = time.monotonic() + max_seconds
    objects = [obj for obj in environment.objects if obj.type.name == "Mesh"]
    objects.sort(key=lambda obj: int(getattr(obj, "byte_size", 0) or 0), reverse=True)
    signatures = []
    for obj in objects[:128]:
        if time.monotonic() >= deadline or len(signatures) >= 8:
            break
        mesh = None
        handler = None
        try:
            mesh = obj.read()
            handler = MeshHandler(mesh)
            handler.process()
            vertices = handler.m_Vertices or []
            vertex_count = len(vertices)
            if vertex_count < 64:
                continue
            signature = _avacrypt_v1_uv_signature(
                handler.m_UV6 or [], handler.m_UV7 or [], vertex_count)
            if signature is None:
                continue
            signatures.append({
                "name": fix(getattr(mesh, "m_Name", "") or ("mesh_%s" % obj.path_id)),
                "path_id": str(obj.path_id),
                "vertex_count": vertex_count,
                "uv_signature": signature,
            })
        except Exception:
            continue
        finally:
            handler = None
            mesh = None
    return signatures


def _avacrypt_v1_menu_evidence(menus):
    """Return whether menus expose four independent V1-like inputs.

    ``_Key0..3`` is a strong material marker, but it is not sufficient to
    start a mesh walk: ordinary avatars can carry a copied material or a
    shader package containing those property names without using AvaCrypt.
    Require four distinct puppet/sub-parameter inputs as a second, cheap
    structural signal.  Names are intentionally not inspected so renamed
    generator branches remain supported.
    """
    unique_parameters = set()
    input_controls = 0
    for menu in menus or []:
        for control in menu.get("controls", []) or []:
            if not isinstance(control, dict):
                continue
            parameters = []
            parameter = fix(control.get("parameter", ""))
            if parameter:
                parameters.append(parameter)
            for value in control.get("sub_parameters", []) or []:
                value = fix(value)
                if value:
                    parameters.append(value)
            # Expression-menu puppet controls are the only controls that
            # legitimately expose parameter vectors.  Keep the synthetic
            # 203 form used by normalized regression fixtures as well.
            control_type = int(control.get("type", 0) or 0)
            if parameters and (control_type in (3, 4, 5, 203) or
                               len(parameters) > 1):
                input_controls += 1
                unique_parameters.update(parameters)
    return input_controls >= 4 and len(unique_parameters) >= 4


def _should_probe_avacrypt_v1(v1_material_count, key_parameter_count=0,
                              menu_evidence=False):
    """Start the expensive mesh probe only after two independent signals."""
    return (int(v1_material_count or 0) > 0 and
            (int(key_parameter_count or 0) >= 4 or bool(menu_evidence)))


def _has_contiguous_v2_markers(markers, minimum=8):
    """Recognize a real multi-bit V2 parameter family without mesh IO."""
    indices = set()
    for marker in markers or []:
        match = re.fullmatch(r"BitKey([0-9]{1,3})", str(marker))
        if match:
            indices.add(int(match.group(1)))
    if len(indices) < minimum:
        return False
    run = 0
    previous = None
    for index in sorted(indices):
        run = run + 1 if previous is not None and index == previous + 1 else 1
        previous = index
        if run >= minimum:
            return True
    return False


def _load_deep_request(path, source_sha256):
    if not path:
        return {}
    if os.path.getsize(path) > 1024 * 1024:
        raise ValueError("deep scan request too large")
    with open(path, encoding="utf-8-sig") as stream:
        request = json.load(stream)
    if (not isinstance(request, dict) or request.get("schema") != 1 or
            request.get("source_sha256", "").upper() != source_sha256.upper()):
        raise ValueError("deep scan request source mismatch")
    controllers = request.get("controllers", [])
    if not isinstance(controllers, list) or len(controllers) > 64:
        raise ValueError("invalid deep scan controller list")
    result = {}
    total = 0
    for row in controllers:
        if not isinstance(row, dict):
            raise ValueError("invalid deep scan controller record")
        path_id = str(row.get("path_id", ""))
        raw_indices = row.get("machine_indices", [])
        if not path_id or not isinstance(raw_indices, list):
            raise ValueError("invalid deep scan target")
        indices = set()
        for value in raw_indices:
            index = _strict_int(value)
            if index is None or not 0 <= index < 4096:
                raise ValueError("invalid deep scan machine index")
            indices.add(index)
        total += len(indices)
        if total > 512:
            raise ValueError("too many deep scan machines")
        if indices:
            result[path_id] = indices
    return result


_REMOTE_GRAPH_TOP_LEVEL_FIELDS = {
    "schema", "graph_schema_version", "source_sha256", "analysis_depth",
    "deep_scan_machine_count", "stats", "controllers", "menus",
    "active_fx_controller_ids", "active_root_menu_ids",
    "expression_parameters", "contact_components",
}


def _merge_incremental_deep_controllers(fast_graph, deep_controllers,
                                        deep_machine_count):
    """Merge only signed deep-controller evidence into a verified fast graph.

    The fast graph remains the authoritative base for menus, contacts,
    expression parameters, and stable parameter ordering.  A deep parser is
    allowed to replace only machines it actually completed.  Any mismatch in
    controller identity, parameter multiset, or machine layout fails closed;
    this keeps a partial/foreign graph from being presented as a complete
    deep result.
    """
    if not isinstance(fast_graph, dict) or set(fast_graph) != _REMOTE_GRAPH_TOP_LEVEL_FIELDS:
        raise ValueError("incremental_fast_graph_schema_invalid")
    if fast_graph.get("graph_schema_version") != "vpf-structural-graph/1":
        raise ValueError("incremental_fast_graph_schema_invalid")
    if fast_graph.get("analysis_depth") != "fast":
        raise ValueError("incremental_fast_graph_not_fast")
    if not isinstance(deep_controllers, dict) or not deep_controllers:
        raise ValueError("incremental_deep_controller_missing")
    merged = copy.deepcopy(fast_graph)
    merged["analysis_depth"] = "targeted_deep"
    merged["deep_scan_machine_count"] = int(deep_machine_count)
    base_by_id = {}
    for controller in merged.get("controllers", []):
        if not isinstance(controller, dict):
            raise ValueError("incremental_fast_controller_invalid")
        path_id = str(controller.get("path_id", ""))
        if not path_id or path_id in base_by_id:
            raise ValueError("incremental_fast_controller_identity_invalid")
        base_by_id[path_id] = controller
    for path_id, deep in deep_controllers.items():
        base = base_by_id.get(str(path_id))
        if not isinstance(deep, dict) or base is None:
            raise ValueError("incremental_deep_controller_identity_invalid")
        if str(deep.get("path_id", "")) != str(path_id):
            raise ValueError("incremental_deep_controller_identity_invalid")
        base_parameters = base.get("parameters", [])
        deep_parameters = deep.get("parameters", [])
        if (not isinstance(base_parameters, list) or
                not isinstance(deep_parameters, list) or
                Counter(base_parameters) != Counter(deep_parameters)):
            # Deep parsing may discover a genuinely new parameter.  It must
            # be handled by a protocol/schema change, never silently merged.
            raise ValueError("incremental_parameter_set_mismatch")
        deep_indices = deep.get("deep_scan_machine_indices", [])
        if (not isinstance(deep_indices, list) or
                any(isinstance(index, bool) or not isinstance(index, int)
                    for index in deep_indices) or
                deep_indices != sorted(set(deep_indices))):
            raise ValueError("incremental_deep_coverage_invalid")
        base_machines = base.get("machines", [])
        deep_machines = deep.get("machines", [])
        if (not isinstance(base_machines, list) or
                not isinstance(deep_machines, list) or
                len(base_machines) != len(deep_machines) or
                any(index < 0 or index >= len(base_machines)
                    for index in deep_indices)):
            raise ValueError("incremental_machine_layout_invalid")
        stable_keys = set(base) | set(deep)
        stable_keys -= {"parameters", "machines", "deep_scan_machine_indices"}
        if any(base.get(key) != deep.get(key) for key in stable_keys):
            raise ValueError("incremental_controller_metadata_mismatch")
        base["deep_scan_machine_indices"] = list(deep_indices)
        for index in deep_indices:
            base["machines"][index] = copy.deepcopy(deep_machines[index])
    return merged


def build_incremental_remote_snapshot(path, fast_graph_path,
                                       deep_request_path):
    """Reparse only signed deep targets while reusing a verified fast graph.

    The source is still hashed in full and UnityPy is still loaded for the
    requested controller evidence.  No lock classification or authorization
    is performed here; this is a data-only extraction optimization.
    """
    print("STAGE|read_model", flush=True)
    source_digest = hashlib.sha256()
    with open(path, "rb") as source_stream:
        for source_chunk in iter(lambda: source_stream.read(1024 * 1024), b""):
            source_digest.update(source_chunk)
    source_sha256 = source_digest.hexdigest().upper()
    deep_targets = _load_deep_request(deep_request_path, source_sha256)
    if not deep_targets:
        raise ValueError("incremental_deep_request_empty")
    if not os.path.isfile(fast_graph_path):
        raise ValueError("incremental_fast_graph_missing")
    if os.path.getsize(fast_graph_path) > 64 * 1024 * 1024:
        raise ValueError("incremental_fast_graph_too_large")
    with open(fast_graph_path, "rb") as fast_stream:
        fast_graph = json.loads(fast_stream.read().decode("utf-8", "strict"))
    if (str(fast_graph.get("source_sha256", "")).upper() != source_sha256 or
            set(fast_graph) != _REMOTE_GRAPH_TOP_LEVEL_FIELDS):
        raise ValueError("incremental_fast_graph_source_mismatch")
    print("STAGE|extract_state_machines", flush=True)
    environment = UnityPy.load(path)
    scripts = script_name_map(environment)
    resource_attribute_maps = _resource_attribute_maps(environment.objects)
    _, _, avatar_diagnostics = _active_avatar_references(environment, scripts)
    exact_binding_indexes = {}
    parameter_hash_names = {
        fix(item.get("name", ""))
        for item in fast_graph.get("expression_parameters", [])
        if isinstance(item, dict) and fix(item.get("name", ""))
    }
    parameter_hash_names.update(_menu_parameter_names(
        fast_graph.get("menus", []) or []))
    deep_controllers = {}
    target_ids = set(deep_targets)
    for obj in environment.objects:
        if obj.type.name != "AnimatorController":
            continue
        path_id = str(obj.path_id)
        if path_id not in target_ids:
            continue
        tree = read_controller(obj)
        if not isinstance(tree, dict):
            raise ValueError("incremental_target_controller_unreadable")
        parsed, _ = controller_json(
            obj, tree, scripts, True, None, None, None,
            parameter_hash_names, None, deep_targets[path_id], False,
            resource_attribute_maps)
        roots = {r["root_game_object"]
                 for r in avatar_diagnostics.get("controller_binding_roots", [])
                 if r["controller"] == path_id}
        writes = [w for machine in parsed.get("machines", [])
                  for state in machine.get("states", [])
                  for field in ("animation_constant_writes",
                                "manual_activation_writes", "animation_object_writes")
                  for w in state.get(field, [])]
        if writes and len(roots) == 1:
            objects = getattr(getattr(obj, "assets_file", None), "objects", {})
            root_id = int(next(iter(roots)))
            cache_key = (id(objects), root_id)
            if cache_key not in exact_binding_indexes:
                try:
                    exact_binding_indexes[cache_key] = _build_exact_binding_index(
                        objects, root_id)
                except Exception:
                    exact_binding_indexes[cache_key] = {
                        "complete": False, "paths": {}}
            binding_index = exact_binding_indexes[cache_key]
            for write in writes:
                write["component_binding"] = _resolve_exact_binding(
                    binding_index, write)
        deep_controllers[path_id] = parsed
    if set(deep_controllers) != target_ids:
        raise ValueError("incremental_target_controller_missing")
    return _merge_incremental_deep_controllers(
        fast_graph, deep_controllers,
        sum(len(indices) for indices in deep_targets.values()))


def build_snapshot(path, deep_request_path=None, return_environment=False,
                   remote_structural=False):
    print("STAGE|read_model", flush=True)
    source_digest = hashlib.sha256()
    with open(path, "rb") as source_stream:
        for source_chunk in iter(lambda: source_stream.read(1024 * 1024), b""):
            source_digest.update(source_chunk)
    source_sha256 = source_digest.hexdigest().upper()
    deep_targets = _load_deep_request(deep_request_path, source_sha256)
    environment = UnityPy.load(path)
    print("STAGE|extract_state_machines", flush=True)
    scripts = script_name_map(environment)
    resource_attribute_maps = _resource_attribute_maps(environment.objects)
    controllers = []
    controller_records = []
    menus = []
    expression_parameters = []
    contacts = []
    stats = {
        "controller_ok": 0,
        "controller_fail": 0,
        "menu_repaired": 0,
        "md5_parameters": 0,
        "unicode_obfuscated": 0,
    }
    # Keep the two public GTAvaCrypt generations separate.  V1 drives four
    # float keys through RadialPuppet controls and materials expose _Key0..3.
    # V2 drives per-bit bool parameters and materials expose _BitKeyN.  The
    # old `parameters`/`material_count` fields are retained as compatibility
    # aliases for consumers of schema 1 snapshots.
    avacrypt = {
        "parameters": [],
        "material_count": 0,
        "leaked": False,
        "v1_parameters": [],
        "v1_material_count": 0,
        "v2_parameters": [],
        "v2_raw_parameter_markers": [],
        "v2_material_count": 0,
        "v2_bit_indices": [],
        "v2_mesh_offset_signatures": [],
        "v2_mesh_probe_status": "not_applicable",
        "v1_mesh_probes": [],
        "v1_mesh_probe_status": "not_applicable",
    }
    shell_protector = {
        "parameters": [],
        "raw_parameter_markers": [],
        "multiplexed": False,
        "direct_key_indices": [],
    }
    for obj in environment.objects:
        object_type = obj.type.name
        if object_type == "AnimatorController":
            tree = read_controller(obj)
            if not isinstance(tree, dict):
                stats["controller_fail"] += 1
                continue
            stats["controller_ok"] += 1
            controller_records.append((obj, tree))
            continue
        if object_type not in ("MonoBehaviour", "Material", "AnimationClip"):
            continue
        # Animation curves are not inputs to password/menu reconstruction.
        # Some third-party bundles contain curve TypeTrees that crash
        # UnityPyBoost, so do not parse those optional diagnostic objects here.
        if object_type == "AnimationClip":
            continue
        if object_type == "Material":
            if remote_structural:
                continue
            # Password reconstruction never depends on parsing material
            # TypeTrees.  Bounded raw marker checks distinguish the public
            # AvaCrypt generations without touching attacker-controlled
            # shader property metadata.
            try:
                raw_material = obj.get_raw_data()
                bit_indices = {
                    int(match.group(1))
                    for match in re.finditer(rb"_BitKey([0-9]{1,3})", raw_material)
                    if 0 <= int(match.group(1)) <= 255
                }
                if bit_indices:
                    avacrypt["v2_material_count"] += 1
                    avacrypt["v2_bit_indices"].extend(bit_indices)
                if all(marker in raw_material for marker in
                       (b"_Key0", b"_Key1", b"_Key2", b"_Key3")):
                    avacrypt["v1_material_count"] += 1
            except Exception:
                pass
            continue
        contact_tree, contact_script = _read_named_mono_safe(
            obj, scripts, {"VRCContactReceiver", "VRCContactSender"})
        if contact_tree is not None:
            contacts.append(contact_json(obj, contact_tree, contact_script))
            continue
        # MonoBehaviour TypeTrees in user bundles are the common place for
        # malformed/custom metadata; protected shaders can also distort
        # Material metadata.  Keep the selected VRChat data objects on the
        # bounds-checked Python reader.
        tree, repaired = read_vrc_mono_safe(obj, scripts)
        # A stock lilToon material may expose _BitKey properties even when no
        # mesh lock is present.  Keep a cheap bounded raw-name census so the
        # detached V2 geometry probe requires an independent parameter-side
        # signal instead of trusting materials alone.
        if not remote_structural:
            try:
                raw_markers = {
                    match.group(0).decode("utf-8", "ignore")
                    for match in re.finditer(rb"BitKey[0-9]{1,3}",
                                              bytes(obj.get_raw_data()))
                }
                avacrypt["v2_raw_parameter_markers"].extend(raw_markers)
                shell_markers = {
                    match.group(1).decode("ascii")
                    for match in re.finditer(
                        rb"(?<![A-Za-z0-9_])(encrypt_lock|encrypt_switch[0-3]|pkey(?:[0-9]{1,3})?)(?![A-Za-z0-9_])",
                        bytes(obj.get_raw_data()))
                }
                shell_protector["raw_parameter_markers"].extend(shell_markers)
            except Exception:
                pass
        if not isinstance(tree, dict):
            continue
        if repaired:
            stats["menu_repaired"] += 1
        if object_type == "MonoBehaviour":
            if isinstance(tree.get("controls"), list):
                menus.append(menu_json(obj, tree))
            parameters = tree.get("parameters")
            if isinstance(parameters, list):
                for parameter in parameters:
                    if not isinstance(parameter, dict):
                        continue
                    name = fix(parameter.get("name", ""))
                    if name:
                        try:
                            default_value = float(parameter.get("defaultValue", 0.0))
                        except (TypeError, ValueError, OverflowError):
                            default_value = 0.0
                        expression_parameters.append({
                            "name": name,
                            "value_type": int(parameter.get("valueType", 0) or 0),
                            "default": default_value,
                            "saved": bool(parameter.get("saved", False)),
                            "network_synced": bool(parameter.get("networkSynced", False)),
                        })
                        if name.startswith("AvaCryptKey"):
                            avacrypt["v1_parameters"].append(name)
                        elif name.startswith("BitKey"):
                            avacrypt["v2_parameters"].append(name)
                        if (name == "encrypt_lock" or
                                re.fullmatch(r"encrypt_switch[0-3]", name) or
                                re.fullmatch(r"pkey(?:[0-9]{1,3})?", name)):
                            shell_protector["parameters"].append(name)
    # AnimationClip constant curves are required for independent numeric
    # Toggle combination locks (for example FBE64F), but parsing every clip in
    # an ordinary shared-parameter Button keypad turns a five-minute LZMA scan
    # into a 15+ minute scan. Decide from the already parsed menu schema and
    # keep the expensive path completely lazy for normal keypad/radial locks.
    numeric_toggle_parameters = set()
    numeric_toggle_count = 0
    for menu in menus:
        for control in menu.get("controls", []):
            label = re.sub(r"<[^>]*>", "", fix(control.get("name", ""))).strip()
            label = label.strip("[]()（）【】 ")
            if int(control.get("type", 0) or 0) == 102 and label.isdigit() and len(label) == 1:
                numeric_toggle_count += 1
                parameter = fix(control.get("parameter", ""))
                if parameter:
                    numeric_toggle_parameters.add(parameter)
    preliminary_contact_gates = fixed_contact_gates(contacts)
    need_numeric_animation_constants = (not remote_structural and
        numeric_toggle_count >= 4 and len(numeric_toggle_parameters) >= 4)
    need_contact_animation_constants = (
        not remote_structural and bool(preliminary_contact_gates))
    need_animation_constants = (
        need_numeric_animation_constants or need_contact_animation_constants)
    gated_sender_ids = {
        str(gate.get("sender_path_id", ""))
        for gate in preliminary_contact_gates
        if gate.get("sender_path_id")
    }
    contact_activation_path_hashes = {
        int(value)
        for contact in contacts
        if contact.get("kind") == "sender" and
           str(contact.get("path_id", "")) in gated_sender_ids
        for value in contact.get("hierarchy_path_hashes", []) or []
    }
    # Resolve the avatar's actual runtime references before touching animation
    # clips. Generated packages commonly retain several copied FX controllers;
    # parsing constant curves from every detached copy turns a small Contact
    # check into minutes of unnecessary work and large transient allocations.
    active_fx_controller_ids, active_root_menu_ids, avatar_diagnostics = (
        _active_avatar_references(environment, scripts))
    active_fx_set = set(active_fx_controller_ids)
    active_button_parameters = _active_menu_button_parameters(
        menus, active_root_menu_ids)
    # Preserve an independent name source for generated AnimatorControllers.
    # VRCFury may strip those names from m_TOS, but the same names remain in
    # VRCExpressionsMenu/VRCExpressionParameters and can be mapped back using
    # Unity's documented CRC32 StringToHash algorithm.
    parameter_hash_names = {
        fix(item.get("name", ""))
        for item in expression_parameters
        if isinstance(item, dict) and fix(item.get("name", ""))
    }
    parameter_hash_names.update(_menu_parameter_names(menus))
    exact_binding_indexes = {}
    for controller_obj, controller_tree in controller_records:
        controller_id = str(controller_obj.path_id)
        requested_machines = deep_targets.get(controller_id)
        include_controller_animation = (
            (need_animation_constants or requested_machines is not None) and
            (not active_fx_set or str(controller_obj.path_id) in active_fx_set)
        )
        activation_filter = (None if requested_machines is not None else
            (contact_activation_path_hashes
             if need_contact_animation_constants else None))
        parameter_filter = (None if requested_machines is not None else
            ((_controller_condition_hashes(controller_tree) -
              _controller_tos_hashes_for_names(
                  controller_tree, numeric_toggle_parameters))
             if need_numeric_animation_constants else None))
        parsed, parameters = controller_json(
            controller_obj, controller_tree, scripts,
            include_controller_animation, activation_filter,
            parameter_filter, numeric_toggle_parameters,
            parameter_hash_names,
            (active_button_parameters
             if not active_fx_set or str(controller_obj.path_id) in active_fx_set
             else None),
            requested_machines,
            not remote_structural,
            resource_attribute_maps)
        controllers.append(parsed)
        roots = {r["root_game_object"] for r in avatar_diagnostics.get("controller_binding_roots", [])
                 if r["controller"] == str(controller_obj.path_id)}
        writes = [w for m in parsed.get("machines", []) for s in m.get("states", [])
                  for field in ("animation_constant_writes", "manual_activation_writes", "animation_object_writes")
                  for w in s.get(field, [])]
        if writes and len(roots) == 1:
            objects = getattr(getattr(controller_obj, "assets_file", None), "objects", {})
            root_id = int(next(iter(roots)))
            cache_key = (id(objects), root_id)
            if cache_key not in exact_binding_indexes:
                try:
                    exact_binding_indexes[cache_key] = _build_exact_binding_index(objects, root_id)
                except Exception:
                    exact_binding_indexes[cache_key] = {"complete": False, "paths": {}}
            binding_index = exact_binding_indexes[cache_key]
            for write in writes:
                write["component_binding"] = _resolve_exact_binding(binding_index, write)
        for name in parameters:
            if is_md5_name(name):
                stats["md5_parameters"] += 1
            if has_unicode_obfuscation(name):
                stats["unicode_obfuscated"] += 1

    avacrypt["v1_parameters"] = sorted(set(avacrypt["v1_parameters"]))
    avacrypt["v2_parameters"] = sorted(set(avacrypt["v2_parameters"]))
    avacrypt["v2_raw_parameter_markers"] = sorted(
        set(avacrypt["v2_raw_parameter_markers"]))
    avacrypt["v2_bit_indices"] = sorted(set(avacrypt["v2_bit_indices"]))
    shell_markers = set(shell_protector["parameters"]) | set(
        shell_protector["raw_parameter_markers"])
    shell_protector["parameters"] = sorted(set(shell_protector["parameters"]))
    shell_protector["raw_parameter_markers"] = sorted(set(
        shell_protector["raw_parameter_markers"]))
    shell_protector["multiplexed"] = {
        "encrypt_lock", "encrypt_switch0", "encrypt_switch1",
        "encrypt_switch2", "encrypt_switch3", "pkey",
    }.issubset(shell_markers)
    shell_protector["direct_key_indices"] = sorted({
        int(match.group(1))
        for name in shell_markers
        for match in [re.fullmatch(r"pkey([0-9]{1,3})", name)]
        if match and 0 <= int(match.group(1)) <= 255
    })
    menu_key_parameters = {
        parameter
        for menu in menus
        for control in menu.get("controls", [])
        for parameter in control.get("sub_parameters", [])
        if parameter.startswith("AvaCryptKey")
    }
    v1_key_parameters = set(avacrypt["v1_parameters"]) | menu_key_parameters
    # Do not require the public parameter names here.  Some authorized V1
    # derivatives rename their four radial parameters while leaving the
    # official mesh/shader transform intact.  The _Key0..3 material signature
    # together with four independent menu inputs starts a bounded probe; the
    # native solver still requires a full-rank UV7/UV8 system, independent
    # train/validation agreement and a separated official key class before it
    # reports any percentages.
    v1_menu_evidence = _avacrypt_v1_menu_evidence(menus)
    if not remote_structural and _should_probe_avacrypt_v1(
            avacrypt["v1_material_count"], len(v1_key_parameters),
            v1_menu_evidence):
        avacrypt["v1_mesh_probes"] = _collect_avacrypt_v1_mesh_probes(environment)
        avacrypt["v1_mesh_probe_status"] = (
            "ok" if avacrypt["v1_mesh_probes"] else "no_usable_v1_mesh")
    elif v1_key_parameters or avacrypt["v1_material_count"]:
        avacrypt["v1_mesh_probe_status"] = "weak_v1_signature"
    avacrypt["parameters"] = list(avacrypt["v1_parameters"])
    avacrypt["material_count"] = avacrypt["v2_material_count"]
    detached_avatar_controls = (
        int(avatar_diagnostics.get("descriptor_count", 0) or 0) > 0 and
        int(avatar_diagnostics.get("custom_expressions_count", 0) or 0) > 0 and
        int(avatar_diagnostics.get("missing_expression_parameters_count", 0) or 0) > 0 and
        int(avatar_diagnostics.get("missing_expression_menu_count", 0) or 0) > 0 and
        int(avatar_diagnostics.get("custom_fx_count", 0) or 0) > 0 and
        int(avatar_diagnostics.get("missing_fx_controller_count", 0) or 0) > 0 and
        not active_fx_controller_ids and not active_root_menu_ids and
        not expression_parameters and not menus and
        _has_contiguous_v2_markers(avacrypt["v2_raw_parameter_markers"]))
    if not remote_structural and detached_avatar_controls:
        avacrypt["v2_mesh_offset_signatures"] = (
            _collect_avacrypt_offset_mesh_signatures(environment))
        avacrypt["v2_mesh_probe_status"] = (
            "ok" if avacrypt["v2_mesh_offset_signatures"]
            else "no_encrypted_mesh_offsets")
    dynamic_contacts = dynamic_contact_parameters(
        preliminary_contact_gates, contacts, controllers)
    dynamic_contact_set = set(dynamic_contacts)
    contact_gates = [
        gate for gate in preliminary_contact_gates
        if fix(gate.get("parameter", "")) not in dynamic_contact_set
    ]
    contact_inputs = [
        {
            "parameter": fix(contact.get("parameter", "")),
            "path_id": contact.get("path_id", ""),
            "dynamic": fix(contact.get("parameter", "")) in dynamic_contact_set,
            "game_object": contact.get("game_object", ""),
            "game_object_name": fix(contact.get("game_object_name", "")),
            "game_object_active": bool(contact.get("game_object_active", False)),
            "enabled": bool(contact.get("enabled", False)),
            "local_only": bool(contact.get("local_only", False)),
            "tags": list(contact.get("tags", []) or []),
            "shape_type": int(contact.get("shape_type", 0) or 0),
            "position": contact.get("position"),
            "local_position": contact.get("local_position"),
            **_contact_binding_metadata(contact),
            "radius": float(contact.get("radius", 0.0) or 0.0),
            "receiver_type": int(contact.get("receiver_type", -1) or 0),
            "allow_self": bool(contact.get("allow_self", False)),
            "allow_others": bool(contact.get("allow_others", False)),
            "matched_senders": [
                {
                    "path_id": sender.get("path_id", ""),
                    "game_object": sender.get("game_object", ""),
                    "game_object_name": fix(sender.get("game_object_name", "")),
                    "game_object_active": bool(sender.get("game_object_active", False)),
                    "enabled": bool(sender.get("enabled", False)),
                    "position": sender.get("position"),
                    "local_position": sender.get("local_position"),
                    **_contact_binding_metadata(sender),
                    "shape_type": int(sender.get("shape_type", 0) or 0),
                    "radius": float(sender.get("radius", 0.0) or 0.0),
                }
                for sender in contacts
                if sender.get("kind") == "sender" and
                set(sender.get("tags", []) or []) &
                set(contact.get("tags", []) or [])
            ],
        }
        for contact in contacts
        if contact.get("kind") == "receiver" and contact.get("parameter")
    ]
    if remote_structural:
        # Only normalized structural facts cross the network.  Resource
        # bodies and client-side lock-family conclusions stay out of this
        # schema; the server derives every classification and plan.
        snapshot = {
            "schema": 1,
            "graph_schema_version": "vpf-structural-graph/1",
            "source_sha256": source_sha256,
            "analysis_depth": "targeted_deep" if deep_targets else "fast",
            "deep_scan_machine_count": sum(len(v) for v in deep_targets.values()),
            "stats": stats,
            "controllers": controllers,
            "menus": menus,
            "active_fx_controller_ids": active_fx_controller_ids,
            "active_root_menu_ids": active_root_menu_ids,
            "expression_parameters": expression_parameters,
            "contact_components": contacts,
        }
    else:
        snapshot = {"schema": 1, "source": os.path.basename(path),
                "source_sha256": source_sha256,
                "analysis_depth": "targeted_deep" if deep_targets else "fast",
                "deep_scan_machine_count": sum(len(v) for v in deep_targets.values()),
                "stats": stats, "controllers": controllers, "menus": menus,
                "active_fx_controller_ids": active_fx_controller_ids,
                "active_root_menu_ids": active_root_menu_ids,
                "expression_parameters": expression_parameters,
                "avatar_diagnostics": avatar_diagnostics,
                "contact_gates": contact_gates,
                "contact_inputs": contact_inputs,
                "dynamic_contact_parameters": dynamic_contacts,
                "avacrypt": avacrypt,
                "shell_protector": shell_protector}
    return (snapshot, environment) if return_environment else snapshot


def _icon_noise(image):
    from PIL import Image, ImageChops, ImageFilter, ImageStat
    rgba = image.convert("RGBA")
    alpha = rgba.getchannel("A")
    rgb = Image.new("RGB", rgba.size, "black")
    rgb.paste(rgba, mask=alpha)
    color = ImageStat.Stat(ImageChops.difference(
        rgb, rgb.filter(ImageFilter.MedianFilter(3)))).mean
    edge = ImageStat.Stat(ImageChops.difference(
        alpha, alpha.filter(ImageFilter.MedianFilter(3)))).mean[0]
    return sum(color) / 3.0 + edge

def _icon_mip_error(high, low):
    """Compare real mip content in premultiplied color, not its hue/noisiness."""
    from PIL import Image, ImageChops, ImageStat
    def premultiplied(image):
        rgba = image.convert("RGBA")
        alpha = rgba.getchannel("A")
        color = Image.new("RGB", rgba.size, "black")
        color.paste(rgba, mask=alpha)
        color.putalpha(alpha)
        return color
    high = premultiplied(high)
    # Resize scalar bands separately to avoid premultiplying a second time.
    reduced = Image.merge("RGBA", tuple(channel.resize(low.size, Image.Resampling.BOX)
                                         for channel in high.split()))
    return sum(ImageStat.Stat(ImageChops.difference(reduced, premultiplied(low))).mean) / 4.0


def _recover_crunch_icon(obj, texture):
    from UnityPy.export.Texture2DConverter import parse_image_data
    from UnityPy.helpers.ResourceReader import get_resource_data
    data = texture.get_image_data()
    matches = []
    for shift in range(1, 16):
        header = data[shift:shift + 19]
        if len(header) != 19 or header[:2] != b"Hx":
            continue
        header_size = int.from_bytes(header[2:4], "big")
        data_size = int.from_bytes(header[6:10], "big")
        width = int.from_bytes(header[12:14], "big")
        height = int.from_bytes(header[14:16], "big")
        if (not 19 <= header_size <= data_size <= 64 * 1024 * 1024 or
                (width, height) != (texture.m_Width, texture.m_Height) or
                not 1 <= header[16] <= 32 or header[17] != 1):
            continue
        try:
            resource = getattr(texture, "m_StreamData", None)
            if resource and resource.path:
                # Read the complete corrected payload, not a truncated slice:
                # Crunch needs its final byte as well as its signature.
                payload = get_resource_data(resource.path, obj.assets_file,
                    resource.offset + shift, data_size)
            else:
                payload = data[shift:shift + data_size]
            if len(payload) != data_size:
                continue
            image = parse_image_data(payload, width, height, texture.m_TextureFormat,
                getattr(obj, "version", (0, 0, 0, 0)), obj.platform,
                getattr(texture, "m_PlatformBlob", None))
            matches.append((image, shift))
        except Exception:
            continue
    if len(matches) != 1:
        raise ValueError("Crunch icon alignment is missing or ambiguous")
    return matches[0]


def _icon_block_layout(texture_format):
    if texture_format in (10, 26, 34, 35, 41, 42, 45, 46):
        return 4, 4, 8
    if texture_format in (11, 12, 24, 25, 27, 36, 43, 44, 47):
        return 4, 4, 16
    if 48 <= texture_format <= 59:
        side = (4, 5, 6, 8, 10, 12)[(texture_format - 48) % 6]
        return side, side, 16
    return None


def _menu_icon_image(obj):
    """Conservative display-only recovery of shifted compressed icon data.

    Never mutate the texture/VRCA. Require the same unique alignment across
    three actual mip levels. No model name, target color or smoothness target.
    """
    texture = obj.read()
    try:
        original = texture.image
    except Exception:
        if obj.type.name == "Texture2D" and texture.m_TextureFormat in (28, 29, 64, 65):
            return _recover_crunch_icon(obj, texture)
        raise
    if obj.type.name != "Texture2D":
        return original, 0
    width, height = texture.m_Width, texture.m_Height
    layout = _icon_block_layout(texture.m_TextureFormat)
    if (layout is None or not 16 <= width <= 2048 or
            not 16 <= height <= 2048 or (getattr(texture, "m_MipCount", 0) or 0) < 3):
        return original, 0
    try:
        from UnityPy.export.Texture2DConverter import parse_image_data
        data = texture.get_image_data()
        levels = []
        offset = 0
        for level in range(3):
            w, h = max(1, width >> level), max(1, height >> level)
            bw, bh, block_bytes = layout
            size = ((w + bw - 1) // bw) * ((h + bh - 1) // bh) * block_bytes
            levels.append((offset, w, h, size))
            offset += size
        if len(data) < offset + 15:
            return original, 0
        candidates = []
        for shift in range(16):
            images = [parse_image_data(data[offset+shift:offset+shift+length],
                    w, h, texture.m_TextureFormat, getattr(obj, "version", (0, 0, 0, 0)), obj.platform,
                    getattr(texture, "m_PlatformBlob", None)) for offset, w, h, length in levels]
            errors = [_icon_mip_error(images[i], images[i + 1]) for i in range(2)]
            if shift == 0 and max(errors) < 4.0:
                return original, 0
            candidates.append((errors, shift, images[0]))
        baseline = candidates[0][0]
        best = min(candidates, key=lambda row: sum(row[0]))
        if best[1] == 0:
            return original, 0
        for pair in range(2):
            ranking = sorted(candidates, key=lambda row: row[0][pair])
            if (ranking[0][1] != best[1] or best[0][pair] > 10.0 or
                    max(best[0][pair], 0.25) * 2.5 >= baseline[pair] or
                    max(best[0][pair], 0.25) * 1.8 >= ranking[1][0][pair]):
                return original, 0
        return best[2], best[1]
    except Exception:
        return original, 0

def _export_menu_icons_from_environment(environment, graph, outdir):
    wanted = set()
    for menu in graph.get("menus", []):
        for control in menu.get("controls", []):
            try:
                pid = int(control.get("icon_path_id") or 0)
                if pid and -(1 << 63) <= pid < (1 << 63):
                    wanted.add(pid)
            except (ValueError, TypeError):
                pass
    if len(wanted) > 2048:
        raise ValueError("too many menu icons")
    os.makedirs(outdir, exist_ok=True)
    ok = repaired = 0
    for obj in environment.objects:
        if obj.path_id not in wanted or obj.type.name not in ("Texture2D", "Sprite"):
            continue
        try:
            if obj.type.name == "Texture2D":
                metadata = obj.read_typetree()
                w, h = metadata.get("m_Width", 0), metadata.get("m_Height", 0)
                if not (0 < w <= 4096 and 0 < h <= 4096):
                    continue
            image, shift = _menu_icon_image(obj)
            image.save(os.path.join(outdir, "ic_v2_%d.png" % obj.path_id))
            ok += 1
            repaired += bool(shift)
        except Exception:
            pass
    print("ICONS_OK|%d|%d|%d" % (ok, repaired, len(wanted) - ok))
    return ok, repaired, len(wanted) - ok


def _preview_pointer_path_id(value):
    value = unwrap(value)
    if not isinstance(value, dict):
        return 0
    try:
        return int(value.get("m_PathID", value.get("path_id", 0)) or 0)
    except (TypeError, ValueError):
        return 0


def _build_preview_parameter_manifest(graph):
    """Build display-only FX controls without weakening raw parameter identity."""
    menu_by_id = {
        str(menu.get("id", "")): menu for menu in graph.get("menus", [])
        if isinstance(menu, dict) and str(menu.get("id", ""))
    }
    labels = {}
    pending = [(str(menu_id), "") for menu_id in graph.get(
        "active_root_menu_ids", []) if str(menu_id) in menu_by_id]
    if not pending:
        pending = [(menu_id, "") for menu_id in menu_by_id]
    visited = set()
    while pending:
        menu_id, parent = pending.pop()
        if menu_id in visited:
            continue
        visited.add(menu_id)
        menu = menu_by_id.get(menu_id, {})
        menu_name = fix(menu.get("name", ""))
        here = parent
        if menu_name:
            here = (parent + " / " + menu_name).strip(" /")
        for control in menu.get("controls", []) or []:
            if not isinstance(control, dict):
                continue
            display = fix(control.get("name", "")) or "未命名控件"
            raw = fix(control.get("parameter", ""))
            if raw and raw not in labels:
                labels[raw] = (here + " / " + display).strip(" /")
            for sub in control.get("sub_parameters", []) or []:
                sub = fix(sub)
                if sub and sub not in labels:
                    labels[sub] = (here + " / " + display).strip(" /")
            submenu = str(control.get("submenu", ""))
            if submenu in menu_by_id:
                pending.append((submenu, (here + " / " + display).strip(" /")))

    active_ids = {str(value) for value in graph.get("active_fx_controller_ids", [])}
    result = []
    seen = set()
    for controller in graph.get("controllers", []) or []:
        if not isinstance(controller, dict):
            continue
        controller_id = str(controller.get("path_id", ""))
        if active_ids and controller_id not in active_ids:
            continue
        for parameter in controller.get("parameter_defaults", []) or []:
            if not isinstance(parameter, dict):
                continue
            raw = fix(parameter.get("name", ""))
            if not raw or raw in seen:
                continue
            seen.add(raw)
            kind = str(parameter.get("type", "float")).lower()
            if kind not in ("bool", "int", "float", "trigger"):
                kind = "float"
            raw_default = parameter.get("default", False if kind == "bool" else 0)
            if kind in ("bool", "trigger"):
                default = 1.0 if bool(raw_default) else 0.0
            else:
                try:
                    default = float(raw_default)
                except (TypeError, ValueError):
                    default = 0.0
            result.append({
                "raw_name": raw,
                "display_name": labels.get(raw, raw),
                "type": kind,
                "default_value": default,
                "controller_path_id": controller_id,
            })
    return result


def _build_preview_parameter_links(graph):
    """Expose only copy drivers that directly feed an animated blend input.

    VRChat evaluates Avatar Parameter Drivers outside Unity's stock Animator.
    The standalone viewer therefore needs the final input-to-effect copies, but
    must not replay unrelated network/synchronization fan-out or cyclic drivers.
    Restricting destinations to parameters consumed by blend trees gives the
    previewer the missing visual bridge without turning every driver in the
    controller into an unconditional write.
    """
    active_ids = {str(value) for value in graph.get("active_fx_controller_ids", [])}
    controllers = [controller for controller in graph.get("controllers", [])
                   if isinstance(controller, dict) and (not active_ids or
                       str(controller.get("path_id", "")) in active_ids)]
    blend_inputs = set()
    for controller in controllers:
        for machine in controller.get("machines", []) or []:
            for state in machine.get("states", []) or []:
                for read in state.get("blend_parameter_reads", []) or []:
                    if isinstance(read, dict) and fix(read.get("parameter", "")):
                        blend_inputs.add(fix(read.get("parameter", "")))
    links = []
    seen = set()
    for controller in controllers:
        for machine in controller.get("machines", []) or []:
            for state in machine.get("states", []) or []:
                for write in state.get("parameter_writes", []) or []:
                    if not isinstance(write, dict) or int(write.get("type", -1)) != 3:
                        continue
                    source = fix(write.get("source", ""))
                    destination = fix(write.get("name", ""))
                    if not source or destination not in blend_inputs:
                        continue
                    key = (source, destination)
                    if key in seen:
                        continue
                    seen.add(key)
                    metadata = write.get("operation_metadata", {})
                    if not isinstance(metadata, dict):
                        metadata = {}
                    links.append({
                        "source": source,
                        "destination": destination,
                        "convert_range": bool(metadata.get("convert_range", False)),
                        "source_min": float(metadata.get("source_min", 0.0) or 0.0),
                        "source_max": float(metadata.get("source_max", 0.0) or 0.0),
                        "destination_min": float(metadata.get("dest_min", 0.0) or 0.0),
                        "destination_max": float(metadata.get("dest_max", 0.0) or 0.0),
                    })
    return links


def _build_preview_manifest(environment, graph, session_nonce):
    """Return a bounded runtime-selection map for the read-only Unity viewer.

    Runtime Unity instance IDs are deliberately excluded: they are process-local
    and cannot identify serialized objects.  The sibling-index chain is only the
    viewer-side locator; every eventual write is re-bound to the serialized
    PathID/class ID and old value by the compatibility writer.
    """
    if not isinstance(session_nonce, str) or not (32 <= len(session_nonce) <= 128):
        raise ValueError("invalid preview session nonce")
    scripts = script_name_map(environment)
    containers = []
    for asset_name, pointer in environment.container.items():
        try:
            obj = pointer.deref()
            if obj is not None and obj.type.name == "GameObject":
                containers.append((asset_name, obj))
        except Exception:
            continue
    if len(containers) != 1:
        raise ValueError("preview requires exactly one avatar prefab container")
    asset_name, root = containers[0]
    objects = getattr(root.assets_file, "objects", {})
    if not isinstance(objects, dict):
        raise ValueError("serialized object table unavailable")

    go_tree_cache = {}
    component_tree_cache = {}
    transform_to_go = {}
    go_to_transform = {}
    for obj in objects.values():
        if obj.type.name != "GameObject":
            continue
        tree = read_typetree_safe(obj)
        if not isinstance(tree, dict):
            continue
        go_tree_cache[obj.path_id] = tree
        for raw in tree.get("m_Component", []) or []:
            component = unwrap(raw)
            cid = _preview_pointer_path_id(component.get("component", {})) \
                if isinstance(component, dict) else 0
            linked = objects.get(cid)
            if linked is not None and linked.type.name in ("Transform", "RectTransform"):
                go_to_transform[obj.path_id] = cid
                transform_to_go[cid] = obj.path_id
                break

    root_transform = go_to_transform.get(root.path_id)
    if not root_transform:
        raise ValueError("avatar prefab root transform unavailable")

    records = []
    visited = set()

    def visit(transform_id, chain, names):
        if transform_id in visited or len(visited) >= 200000:
            return
        visited.add(transform_id)
        go_id = transform_to_go.get(transform_id)
        tree = go_tree_cache.get(go_id)
        transform_obj = objects.get(transform_id)
        transform_tree = read_typetree_safe(transform_obj) if transform_obj else None
        if go_id is None or not isinstance(tree, dict) or not isinstance(transform_tree, dict):
            return
        name = fix(tree.get("m_Name", ""))
        path_names = names + [name]
        components = []
        type_ordinals = {}
        for raw in tree.get("m_Component", []) or []:
            component = unwrap(raw)
            cid = _preview_pointer_path_id(component.get("component", {})) \
                if isinstance(component, dict) else 0
            linked = objects.get(cid)
            if linked is None:
                continue
            type_name = linked.type.name
            if type_name == "MonoBehaviour":
                type_name = mono_script_name(linked, scripts) or type_name
            ordinal = type_ordinals.get(type_name, 0)
            type_ordinals[type_name] = ordinal + 1
            ctree = component_tree_cache.get(cid)
            if ctree is None:
                ctree = read_typetree_safe(linked)
                component_tree_cache[cid] = ctree
            has_enabled = isinstance(ctree, dict) and "m_Enabled" in ctree
            enabled = bool(ctree.get("m_Enabled")) if has_enabled else True
            components.append({
                "path_id": str(cid),
                "class_id": int(linked.type.value),
                "type_name": type_name,
                "type_ordinal": ordinal,
                "has_enabled": has_enabled,
                "enabled": enabled,
                "selection_id": hashlib.sha256((session_nonce + "|c|" +
                    str(cid) + "|" + str(linked.type.value)).encode("utf-8")).hexdigest(),
            })
        records.append({
            "game_object_path_id": str(go_id),
            "class_id": 1,
            "name": name,
            "hierarchy_path": "/".join(path_names),
            "sibling_chain": list(chain),
            "active": bool(tree.get("m_IsActive", True)),
            "selection_id": hashlib.sha256((session_nonce + "|g|" +
                str(go_id) + "|1").encode("utf-8")).hexdigest(),
            "components": components,
        })
        for sibling, child in enumerate(transform_tree.get("m_Children", []) or []):
            child_id = _preview_pointer_path_id(child)
            if child_id:
                visit(child_id, chain + [sibling], path_names)

    visit(root_transform, [], [])
    if not records:
        raise ValueError("avatar hierarchy is empty")
    fx_assets = []
    active_fx = {str(value) for value in graph.get("active_fx_controller_ids", [])}
    for name, pointer in environment.container.items():
        try:
            linked = pointer.deref()
            if linked is not None and str(linked.path_id) in active_fx:
                fx_assets.append(name)
        except Exception:
            continue
    menus = []
    for menu in graph.get("menus", []):
        if not isinstance(menu, dict):
            continue
        preview_menu = dict(menu)
        preview_menu["controls"] = []
        for control in menu.get("controls", []):
            if not isinstance(control, dict):
                continue
            preview_control = dict(control)
            preview_control["sub_parameters"] = control.get(
                "preview_sub_parameters", control.get("sub_parameters", []))
            preview_control.pop("preview_sub_parameters", None)
            preview_menu["controls"].append(preview_control)
        menus.append(preview_menu)
    menu_ids = {str(menu.get("id", "")) for menu in menus}
    roots = [str(value) for value in graph.get("active_root_menu_ids", [])
             if str(value) in menu_ids]
    if not roots and menus:
        referenced = {str(control.get("submenu", "")) for menu in menus
                      for control in menu.get("controls", []) if isinstance(control, dict)}
        possible = [menu for menu in menus if str(menu.get("id", "")) not in referenced]
        # Match the text viewer's useful root fallback, without flattening or
        # recursively expanding shared/cyclic submenu nodes.
        chosen = max(possible or menus, key=lambda menu: len(menu.get("controls", [])))
        roots = [str(chosen.get("id", ""))]
    return {
        "schema": 1,
        "session_nonce": session_nonce,
        "source_sha256": graph.get("source_sha256", ""),
        "asset_name": asset_name,
        "root_game_object_path_id": str(root.path_id),
        "objects": records,
        "fx_parameters": _build_preview_parameter_manifest(graph),
        "parameter_links": _build_preview_parameter_links(graph),
        "fx_asset_name": fx_assets[0] if len(fx_assets) == 1 else "",
        "root_menu_ids": roots,
        "menus": menus,
    }


def export_menu_icons(path, graph_path, outdir):
    if os.path.getsize(graph_path) > 64 * 1024 * 1024:
        raise ValueError("menu graph too large")
    with open(graph_path, encoding="utf-8-sig") as stream:
        graph = json.load(stream)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest().upper() != graph.get("source_sha256", "").upper():
        raise ValueError("menu graph source mismatch")
    environment = UnityPy.load(path)
    _export_menu_icons_from_environment(environment, graph, outdir)
    return 0


def _write_remote_graph(path, snapshot):
    """Write the exact deterministic bytes whose SHA-256 is submitted.

    Binary output prevents BOM/newline translation.  allow_nan=False avoids
    Python-only NaN/Infinity spellings that other JSON runtimes interpret
    differently.
    """
    normalized = dict(snapshot)
    if normalized.get("graph_schema_version") == "vpf-structural-graph/1":
        source_sha256 = str(normalized.get("source_sha256", ""))
        if not re.fullmatch(r"[A-Fa-f0-9]{64}", source_sha256):
            raise ValueError("remote graph source SHA-256 is invalid")
        # The signed remote protocol and Linux worker use one canonical
        # lowercase spelling.  Local legacy snapshots keep their historical
        # uppercase digest, but bytes sent to the server must not depend on
        # that display convention.
        normalized["source_sha256"] = source_sha256.lower()
    payload = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"),
                         sort_keys=True, allow_nan=False).encode("utf-8")
    with open(path, "xb") as stream:
        stream.write(payload)
    return payload


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 3 and argv[0] == "--remote-graph":
        snapshot = build_snapshot(argv[1], remote_structural=True)
        payload = _write_remote_graph(argv[2], snapshot)
        print("REMOTE_GRAPH_OK|%d|%d|%d" % (
            snapshot["stats"]["controller_ok"], len(snapshot["menus"]),
            len(payload)))
        return 0
    if len(argv) == 4 and argv[0] == "--remote-deep-request":
        snapshot = build_snapshot(argv[2], argv[1], remote_structural=True)
        payload = _write_remote_graph(argv[3], snapshot)
        print("REMOTE_GRAPH_DEEP_OK|%d|%d|%d|%d" % (
            snapshot["stats"]["controller_ok"], len(snapshot["menus"]),
            snapshot["deep_scan_machine_count"], len(payload)))
        return 0
    if len(argv) == 5 and argv[0] == "--remote-deep-from-fast":
        snapshot = build_incremental_remote_snapshot(argv[3], argv[1], argv[2])
        payload = _write_remote_graph(argv[4], snapshot)
        print("REMOTE_GRAPH_DEEP_REUSE_OK|%d|%d|%d|%d" % (
            snapshot["stats"]["controller_ok"], len(snapshot["menus"]),
            snapshot["deep_scan_machine_count"], len(payload)))
        return 0
    if len(argv) == 4 and argv[0] == "--menu-icons":
        return export_menu_icons(argv[1], argv[2], argv[3])
    if len(argv) == 4 and argv[0] == "--snapshot-with-icons":
        snapshot, environment = build_snapshot(argv[1], return_environment=True)
        icons_ok = False
        try:
            _export_menu_icons_from_environment(environment, snapshot, argv[3])
            icons_ok = True
        except Exception as exc:
            # Preserve the menu graph even if an unusual texture cannot be
            # exported; the UI can still show text and retry the legacy icon
            # path without re-running the state-machine extraction.
            print("ICONS_ERROR|%s" % str(exc).replace("\n", " "), flush=True)
        with open(argv[2], "w", encoding="utf-8", newline="\n") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, separators=(",", ":"))
        print(("SNAPSHOT_ICONS_OK" if icons_ok else "SNAPSHOT_OK") + "|%d|%d" % (
            snapshot["stats"]["controller_ok"], len(snapshot["menus"])))
        return 0
    if len(argv) == 5 and argv[0] == "--preview-manifest":
        snapshot, environment = build_snapshot(argv[1], return_environment=True)
        manifest = _build_preview_manifest(environment, snapshot, argv[4])
        try:
            _export_menu_icons_from_environment(environment, snapshot,
                os.path.join(os.path.dirname(os.path.abspath(argv[3])), "icons"))
        except Exception as exc:
            print("PREVIEW_ICONS_WARNING|%s" % str(exc).replace("\n", " "), flush=True)
        with open(argv[2], "w", encoding="utf-8", newline="\n") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, separators=(",", ":"))
        with open(argv[3], "w", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, ensure_ascii=False, separators=(",", ":"))
        print("PREVIEW_MANIFEST_OK|%d|%d" % (
            len(manifest["objects"]), len(manifest["fx_parameters"])))
        return 0
    if len(argv) == 4 and argv[0] == "--deep-request":
        snapshot = build_snapshot(argv[2], argv[1])
        with open(argv[3], "w", encoding="utf-8", newline="\n") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, separators=(",", ":"))
        print("SNAPSHOT_DEEP_OK|%d|%d|%d" % (
            snapshot["stats"]["controller_ok"], len(snapshot["menus"]),
            snapshot["deep_scan_machine_count"]))
        return 0
    if len(argv) != 2:
        print("ERR|用法: vrca_extract_graph.py input.vrca output.json")
        return 2
    snapshot = build_snapshot(argv[0])
    with open(argv[1], "w", encoding="utf-8", newline="\n") as stream:
        json.dump(snapshot, stream, ensure_ascii=False, separators=(",", ":"))
    print("SNAPSHOT_OK|%d|%d" % (snapshot["stats"]["controller_ok"], len(snapshot["menus"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
