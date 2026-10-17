using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEngine;

namespace VPF.ProjectRecovery
{
    // Trusted, explicitly invoked editor tools. No InitializeOnLoad or model-code execution.
    public sealed class VPFRecoveryAssistant : EditorWindow
    {
        [Serializable] public sealed class RecoveryReport
        {
            public int schema;
            public string sourceSha256, modelRoot, unityVersion, sourceUnityVersion, status, mainPrefab;
            public string[] prefabs, warnings;
            public Finding[] findings;
            public Repair[] repairs;
            public bool unityImportVerified, runtimeVerified, passwordLockChanged, findingsTruncated;
        }
        [Serializable] public sealed class Finding
        {
            public string kind, path, guid, fileId;
        }
        [Serializable] public sealed class Repair
        {
            public string kind, path, from_guid, to_reference, expectedType;
        }
        [Serializable] public sealed class ImportCheck
        {
            public bool ok, prefabLoaded;
            public int prefabsChecked, missingScripts, nullMaterials, missingShaders, shaderErrors;
            public int renderers, meshes, submeshes, skinnedRenderers, bones, blendShapes, animationClips;
            public int invalidMeshes, missingBones, invalidAnimations, emptyAnimations, unresolvedReferences, sdkScriptsResolved;
            public int sdkReferenceTypeMismatch;
            public string unityVersion, sourceSha256;
            public List<string> issues = new List<string>();
            public List<string> sdkScriptReferences = new List<string>();
        }

        TextAsset selected;
        RecoveryReport report;
        ImportCheck check;
        Vector2 scroll;
        string error;
        TextAsset[] reports = new TextAsset[0];

        [MenuItem("VPF/工程恢复助手")]
        public static void Open() { GetWindow<VPFRecoveryAssistant>("VPF 工程恢复"); }

        void OnEnable() { RefreshReports(); }
        void RefreshReports()
        {
            reports = AssetDatabase.FindAssets("VPFRecoveryReport t:TextAsset", new[] {"Assets/VPFRecovered"})
                .Select(g => AssetDatabase.LoadAssetAtPath<TextAsset>(AssetDatabase.GUIDToAssetPath(g)))
                .Where(a => a != null).OrderBy(a => AssetDatabase.GetAssetPath(a)).ToArray();
            if (selected == null && reports.Length == 1) SelectReport(reports[0]);
        }
        void SelectReport(TextAsset asset)
        {
            selected = asset; check = null; error = null; report = null;
            try
            {
                if (asset == null) return;
                if (asset.text.Length > 8 * 1024 * 1024) throw new Exception("恢复报告超过大小限制。");
                var r = JsonUtility.FromJson<RecoveryReport>(asset.text);
                if (r == null || r.schema != 1 || !ValidRoot(r.modelRoot) || !ValidAsset(r.mainPrefab, r.modelRoot))
                    throw new Exception("不是有效的 VPF 恢复报告。");
                if (AssetDatabase.GetAssetPath(asset) != r.modelRoot + "/VPFRecoveryReport.json")
                    throw new Exception("恢复报告和资源目录不匹配。");
                report = r;
            }
            catch (Exception ex) { error = ex.Message; }
        }
        static bool ValidRoot(string p)
        {
            return p != null && System.Text.RegularExpressions.Regex.IsMatch(p, "^Assets/VPFRecovered/[0-9a-f]{20}$");
        }
        static bool ValidAsset(string p, string root)
        {
            return p != null && p.StartsWith(root + "/", StringComparison.Ordinal)
                && !p.Contains("..") && !p.Contains('\\') && !p.Contains(':');
        }

        void OnGUI()
        {
            EditorGUILayout.LabelField("工程恢复助手", EditorStyles.boldLabel);
            EditorGUILayout.HelpBox("先等待 Unity 完成导入。这里检查恢复数据，不会移除模型的密码锁，也不会删除缺失组件。", MessageType.Info);
            if (GUILayout.Button("刷新模型列表")) RefreshReports();
            if (reports.Length > 1)
            {
                int index = Array.IndexOf(reports, selected);
                int next = EditorGUILayout.Popup("选择模型", Math.Max(0, index), reports.Select(a => AssetDatabase.GetAssetPath(a).Split('/')[2]).ToArray());
                if (next != index) SelectReport(reports[next]);
            }
            var input = (TextAsset)EditorGUILayout.ObjectField("恢复报告", selected, typeof(TextAsset), false);
            if (input != selected) SelectReport(input);
            if (!string.IsNullOrEmpty(error)) EditorGUILayout.HelpBox(error, MessageType.Error);
            if (report == null) { EditorGUILayout.HelpBox("导入资源包或打开完整工程后，选择 VPFRecoveryReport 文件。", MessageType.Info); return; }
            EditorGUILayout.LabelField("建议 Unity", report.unityVersion);
            EditorGUILayout.LabelField("结果", StatusText(report.status));
            EditorGUILayout.BeginHorizontal();
            if (GUILayout.Button("定位主模型")) Ping(report.mainPrefab);
            if (GUILayout.Button("创建预览场景")) CreateScene();
            EditorGUILayout.EndHorizontal();
            if (GUILayout.Button("检查组件、材质和资源引用")) check = Verify(report);
            scroll = EditorGUILayout.BeginScrollView(scroll);
            if (check != null)
            {
                EditorGUILayout.HelpBox(check.ok ? "基础导入检查通过。效果仍需在场景中确认。" : "发现需要处理的依赖或资源问题；没有自动删改模型。", check.ok ? MessageType.Info : MessageType.Warning);
                EditorGUILayout.LabelField("网格 / 子网格", check.meshes + " / " + check.submeshes);
                EditorGUILayout.LabelField("蒙皮 / 骨骼 / 形变", check.skinnedRenderers + " / " + check.bones + " / " + check.blendShapes);
                EditorGUILayout.LabelField("动画", check.animationClips.ToString());
                foreach (var issue in check.issues) EditorGUILayout.SelectableLabel(issue, EditorStyles.wordWrappedLabel, GUILayout.Height(36));
            }
            var findings = report.findings ?? new Finding[0];
            if (findings.Length > 0) EditorGUILayout.LabelField("导出时发现的缺失依赖", EditorStyles.boldLabel);
            foreach (var finding in findings.Take(200))
            {
                EditorGUILayout.BeginHorizontal();
                EditorGUILayout.LabelField(finding.kind == "missing_script" ? "脚本缺失" : "资源引用缺失", GUILayout.Width(100));
                if (GUILayout.Button(finding.path, EditorStyles.linkLabel)) Ping(finding.path);
                EditorGUILayout.EndHorizontal();
            }
            EditorGUILayout.HelpBox("自定义 Shader/C# 原始源码不能由构建包完整恢复；近似 Shader 或未知依赖不会被当成原版效果。资源包不附重复 SDK，请先安装报告要求的版本。", MessageType.Info);
            EditorGUILayout.EndScrollView();
        }
        static string StatusText(string s)
        {
            if (s == "partial_recovery") return "部分恢复，需要补齐脚本或依赖";
            if (s == "needs_dependencies") return "数据已恢复，需要确认依赖/Shader";
            return "可恢复数据已整理，等待 Unity 和效果确认";
        }
        static void Ping(string path)
        {
            var asset = AssetDatabase.LoadMainAssetAtPath(path);
            if (asset != null) { Selection.activeObject = asset; EditorGUIUtility.PingObject(asset); }
        }
        void CreateScene()
        {
            if (!EditorSceneManager.SaveCurrentModifiedScenesIfUserWantsTo()) return;
            var prefab = AssetDatabase.LoadAssetAtPath<GameObject>(report.mainPrefab);
            if (prefab == null) { error = "主模型尚未完成导入或 Prefab 无法读取。"; return; }
            var scene = EditorSceneManager.NewScene(NewSceneSetup.DefaultGameObjects, NewSceneMode.Single);
            var instance = (GameObject)PrefabUtility.InstantiatePrefab(prefab, scene);
            Selection.activeGameObject = instance;
            var rendererBounds = instance.GetComponentsInChildren<Renderer>(true);
            if (rendererBounds.Length > 0)
            {
                var bounds = rendererBounds[0].bounds;
                foreach (var renderer in rendererBounds.Skip(1)) bounds.Encapsulate(renderer.bounds);
                if (SceneView.lastActiveSceneView != null) SceneView.lastActiveSceneView.Frame(bounds, false);
            }
            string path = AssetDatabase.GenerateUniqueAssetPath(report.modelRoot + "/VPFPreview.unity");
            EditorSceneManager.SaveScene(scene, path);
        }
        static void Issue(ImportCheck c, string message)
        {
            if (c.issues.Count < 200) c.issues.Add(message);
        }
        static bool SpecialBuiltin(string guid)
        {
            return guid == "0000000000000000e000000000000000" || guid == "0000000000000000f000000000000000" || guid == new string('0', 32);
        }
        public static ImportCheck Verify(RecoveryReport r)
        {
            var c = new ImportCheck { unityVersion = Application.unityVersion, sourceSha256 = r.sourceSha256 };
            foreach (var path in new[] {
                "Packages/com.vrchat.avatars/Runtime/VRCSDK/Plugins/VRCSDK3A.dll",
                "Packages/com.vrchat.base/Runtime/VRCSDK/Plugins/VRC.SDK3.Dynamics.Constraint.dll",
                "Packages/com.vrchat.base/Runtime/VRCSDK/Plugins/VRCCore-Editor.dll",
                "Packages/com.vrchat.base/Runtime/VRCSDK/Plugins/VRC.SDK3.Dynamics.PhysBone.dll",
                "Packages/com.vrchat.base/Runtime/VRCSDK/Plugins/VRC.SDK3.Dynamics.Contact.dll"})
            {
                foreach (var script in AssetDatabase.LoadAllAssetsAtPath(path).OfType<MonoScript>())
                {
                    var type = script.GetClass();
                    if (type == null) continue;
                    string guid; long localId;
                    if (AssetDatabase.TryGetGUIDAndLocalFileIdentifier(script, out guid, out localId))
                        c.sdkScriptReferences.Add(type.FullName + "|" + localId + "|" + guid);
                }
            }
            foreach (var repair in r.repairs ?? new Repair[0])
            {
                if (repair.kind != "sdk_script_reference") continue;
                var match = System.Text.RegularExpressions.Regex.Match(repair.to_reference, "fileID: (-?[0-9]+), guid: ([0-9a-f]{32})");
                if (!match.Success || !c.sdkScriptReferences.Contains(repair.expectedType + "|" + match.Groups[1].Value + "|" + match.Groups[2].Value))
                    c.sdkReferenceTypeMismatch++;
            }
            var meshes = new HashSet<int>();
            foreach (string path in r.prefabs ?? new[] {r.mainPrefab})
            {
                if (!ValidAsset(path, r.modelRoot)) throw new Exception("Prefab path is outside model scope.");
                var prefab = AssetDatabase.LoadAssetAtPath<GameObject>(path);
                if (prefab == null) { Issue(c, "Prefab 无法载入：" + path); continue; }
                c.prefabsChecked++;
                if (path == r.mainPrefab) c.prefabLoaded = true;
                foreach (Transform t in prefab.GetComponentsInChildren<Transform>(true))
                {
                    c.missingScripts += GameObjectUtility.GetMonoBehavioursWithMissingScriptCount(t.gameObject);
                    foreach (MonoBehaviour component in t.GetComponents<MonoBehaviour>())
                    {
                        if (component != null && component.GetType().Namespace != null && component.GetType().Namespace.StartsWith("VRC", StringComparison.Ordinal))
                            c.sdkScriptsResolved++;
                    }
                }
                foreach (Renderer renderer in prefab.GetComponentsInChildren<Renderer>(true))
                {
                    c.renderers++;
                    foreach (var material in renderer.sharedMaterials)
                    {
                        if (material == null) { c.nullMaterials++; continue; }
                        if (material.shader == null || material.shader.name == "Hidden/InternalErrorShader") c.missingShaders++;
                        else if (ShaderUtil.ShaderHasError(material.shader)) c.shaderErrors++;
                    }
                    Mesh mesh = null;
                    var skin = renderer as SkinnedMeshRenderer;
                    if (skin != null)
                    {
                        c.skinnedRenderers++; c.bones += skin.bones.Length;
                        c.missingBones += skin.bones.Count(b => b == null);
                        mesh = skin.sharedMesh;
                    }
                    else
                    {
                        var filter = renderer.GetComponent<MeshFilter>();
                        if (filter != null) mesh = filter.sharedMesh;
                    }
                    if (mesh != null && meshes.Add(mesh.GetInstanceID()))
                    {
                        c.meshes++; c.submeshes += mesh.subMeshCount; c.blendShapes += mesh.blendShapeCount;
                        if (mesh.vertexCount <= 0 || mesh.subMeshCount <= 0) c.invalidMeshes++;
                    }
                    else if (mesh == null && (skin != null || renderer is MeshRenderer)) c.invalidMeshes++;
                }
            }
            foreach (string guid in AssetDatabase.FindAssets("t:AnimationClip", new[] {r.modelRoot}))
            {
                var clip = AssetDatabase.LoadAssetAtPath<AnimationClip>(AssetDatabase.GUIDToAssetPath(guid));
                if (clip == null) { c.invalidAnimations++; continue; }
                c.animationClips++;
                if (!AnimationUtility.GetCurveBindings(clip).Any() && !AnimationUtility.GetObjectReferenceCurveBindings(clip).Any())
                    c.emptyAnimations++;
            }
            foreach (var finding in r.findings ?? new Finding[0])
            {
                if (SpecialBuiltin(finding.guid)) continue;
                if (string.IsNullOrEmpty(AssetDatabase.GUIDToAssetPath(finding.guid))) c.unresolvedReferences++;
            }
            if (c.missingScripts > 0) Issue(c, "缺失脚本组件：" + c.missingScripts);
            if (c.nullMaterials > 0) Issue(c, "缺失材质槽：" + c.nullMaterials);
            if (c.missingShaders + c.shaderErrors > 0) Issue(c, "缺失/编译错误 Shader：" + (c.missingShaders + c.shaderErrors));
            if (c.missingBones > 0) Issue(c, "未恢复骨骼引用：" + c.missingBones);
            if (c.invalidMeshes > 0) Issue(c, "缺失或空网格：" + c.invalidMeshes);
            if (c.invalidAnimations > 0) Issue(c, "不可读动画：" + c.invalidAnimations);
            if (c.emptyAnimations > 0) Issue(c, "无曲线动画（可能本来用于占位）：" + c.emptyAnimations);
            if (c.sdkReferenceTypeMismatch > 0) Issue(c, "SDK 引用类型不匹配：" + c.sdkReferenceTypeMismatch);
            c.ok = c.prefabLoaded && c.missingScripts == 0 && c.invalidMeshes == 0 && c.missingBones == 0
                && c.missingShaders == 0 && c.shaderErrors == 0 && c.unresolvedReferences == 0 && c.sdkReferenceTypeMismatch == 0 && c.invalidAnimations == 0;
            return c;
        }
        // Explicit CLI entry for product QA; not called automatically on user import.
        public static void BatchVerify()
        {
            var outputArg = Environment.GetCommandLineArgs();
            int index = Array.IndexOf(outputArg, "-vpfReportOut");
            if (index < 0 || index + 1 >= outputArg.Length) throw new Exception("Missing QA receipt path.");
            var results = new List<ImportCheck>();
            foreach (string guid in AssetDatabase.FindAssets("VPFRecoveryReport t:TextAsset", new[] {"Assets/VPFRecovered"}))
            {
                var asset = AssetDatabase.LoadAssetAtPath<TextAsset>(AssetDatabase.GUIDToAssetPath(guid));
                var r = JsonUtility.FromJson<RecoveryReport>(asset.text);
                if (r.schema != 1 || !ValidRoot(r.modelRoot)) throw new Exception("Invalid recovery report.");
                results.Add(Verify(r));
            }
            if (results.Count != 1) throw new Exception("QA expects exactly one source.");
            File.WriteAllText(outputArg[index + 1], JsonUtility.ToJson(results[0], true));
            Debug.Log("VPF_UNITY_IMPORT_VERIFIED|ok=" + results[0].ok + "|prefab=" + results[0].prefabLoaded);
        }
    }
}
