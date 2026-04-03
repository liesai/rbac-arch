import { useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { Shield, Users, Server, Activity, CheckCircle2, XCircle, Download, Wand2, Check, Settings, LayoutDashboard, Save, Search, ChevronLeft, ChevronRight, Plus, Trash2 } from "lucide-react";
import toast, { Toaster } from "react-hot-toast";

const COLORS = ["#153a5b", "#0f8b8d", "#d9822b", "#d95d7a", "#6d8299"];
const CONTROL_CLASS = "min-h-11 rounded-lg border border-slate-300/80 bg-white/90 px-3 py-2 text-sm text-slate-700 transition hover:bg-white";
const INPUT_CLASS = "min-h-11 rounded-lg border border-slate-300/80 bg-white/90 px-3 py-2 text-sm text-slate-900";
const TAB_CLASS = "min-h-11 rounded-lg px-3 py-2 text-sm font-medium";

function normalizeMatrix(response) {
  const rows = response?.matrix?.matrix ?? response?.matrix ?? [];
  if (!Array.isArray(rows)) return [];
  return rows.map((row, idx) => {
    const roles = Array.isArray(row.roles_assigned ?? row.roles)
      ? (row.roles_assigned ?? row.roles)
      : [];
    return {
      group_id: row.group_id || `group-${idx}`,
      display_name: row.display_name || row.group_id || `Group ${idx + 1}`,
      members_count: Number(row.members_count ?? 0) || 0,
      owner: row.owner || "",
      scope: row.scope || "/",
      tags: row.tags || {},
      naming_ok: Boolean(row.naming_ok ?? true),
      roles: roles
        .map((role) => ({
          name: role?.role ?? role?.name ?? String(role ?? "").trim(),
          data_access: Boolean(role?.data_access_permitted ?? role?.data_access),
          security_admin: Boolean(role?.security_admin_permitted ?? role?.security_admin),
          config_modify: Boolean(role?.config_modify_permitted ?? role?.config_modify),
          billing_read: Boolean(role?.billing_read_permitted ?? role?.billing_read),
        }))
        .filter((role) => role.name),
    };
  });
}

function prettyJson(value) {
  return JSON.stringify(value ?? {}, null, 2);
}

function parseJsonField(label, text) {
  try {
    return { ok: true, value: JSON.parse(text || "null") };
  } catch (error) {
    return { ok: false, error: `${label}: ${error.message}` };
  }
}

function severityTone(level) {
  switch (String(level || "").toUpperCase()) {
    case "CRITICAL":
      return "bg-red-100 text-red-700";
    case "HIGH":
      return "bg-orange-100 text-orange-700";
    case "MEDIUM":
      return "bg-amber-100 text-amber-700";
    case "LOW":
      return "bg-slate-100 text-slate-700";
    default:
      return "bg-indigo-100 text-indigo-700";
  }
}

function confidenceTone(level) {
  switch (String(level || "").toLowerCase()) {
    case "high":
      return "bg-emerald-100 text-emerald-700";
    case "medium":
      return "bg-amber-100 text-amber-700";
    default:
      return "bg-slate-100 text-slate-700";
  }
}

function paginate(items, page, pageSize) {
  const start = (page - 1) * pageSize;
  return items.slice(start, start + pageSize);
}

function updateObjectKey(source, oldKey, newKey, value) {
  const next = {};
  for (const [key, currentValue] of Object.entries(source || {})) {
    if (key === oldKey) {
      next[newKey] = value;
    } else {
      next[key] = currentValue;
    }
  }
  return next;
}

export default function App() {
  const [apiEndpoint] = useState(
    window.__RBAC_API__ || import.meta.env.VITE_API_BASE || "/api",
  );
  const [route, setRoute] = useState(() => (
    window.location.pathname === "/policy-studio" ? "policy" : "dashboard"
  ));
  const [dashboardTab, setDashboardTab] = useState("overview");
  const [matrixData, setMatrixData] = useState([]);
  const [matrixSummary, setMatrixSummary] = useState(null);
  const [risksData, setRisksData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [importJob, setImportJob] = useState(null);
  const [configSource, setConfigSource] = useState("default");
  const [topRisks, setTopRisks] = useState([]);
  const [overrideSuggestions, setOverrideSuggestions] = useState([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [applyingOverrideId, setApplyingOverrideId] = useState("");
  const [riskSearch, setRiskSearch] = useState("");
  const [riskSeverityFilter, setRiskSeverityFilter] = useState("ALL");
  const [matrixSearch, setMatrixSearch] = useState("");
  const [matrixPage, setMatrixPage] = useState(1);
  const [findingsPage, setFindingsPage] = useState(1);
  const [overrideSearch, setOverrideSearch] = useState("");
  const [overrideConfidenceFilter, setOverrideConfidenceFilter] = useState("ALL");
  const [filters, setFilters] = useState({
    owner: "",
    tag: "",
    scope: "",
    namingOnly: false,
    orphanOnly: false,
    minMembers: "",
    maxMembers: "",
  });

  useEffect(() => {
    void refreshAll();
  }, []);

  useEffect(() => {
    if (route === "dashboard" && dashboardTab === "overrides" && overrideSuggestions.length === 0 && !catalogLoading) {
      void refreshOverrideSuggestions();
    }
  }, [route, dashboardTab, overrideSuggestions.length, catalogLoading]);

  useEffect(() => {
    if (!importJob?.job_id) return undefined;
    if (importJob.status === "completed" || importJob.status === "failed") return undefined;

    const timer = window.setInterval(async () => {
      try {
        const res = await fetch(`${apiEndpoint}/upload-config/jobs/${importJob.job_id}`);
        if (!res.ok) throw new Error(`Import job poll failed: ${res.status}`);
        const body = await res.json();
        const job = body?.job || null;
        if (!job) return;
        setImportJob(job);

        if (job.status === "completed") {
          setUploading(false);
          toast.success(job.message || `Import termine: ${job.total_groups || 0} groupes`);
          await refreshAll();
        } else if (job.status === "failed") {
          setUploading(false);
          toast.error(job.error || "Import echoue");
        }
      } catch (err) {
        setUploading(false);
        toast.error(String(err));
      }
    }, 1500);

    return () => window.clearInterval(timer);
  }, [apiEndpoint, importJob?.job_id, importJob?.status]);

  useEffect(() => {
    function handlePopState() {
      setRoute(window.location.pathname === "/policy-studio" ? "policy" : "dashboard");
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  function navigate(nextRoute) {
    const nextPath = nextRoute === "policy" ? "/policy-studio" : "/";
    window.history.pushState({}, "", nextPath);
    setRoute(nextRoute);
  }

  function buildFilterQuery() {
    const params = new URLSearchParams();
    if (filters.owner.trim()) params.set("owner_filter", filters.owner.trim());
    if (filters.tag.trim()) params.set("tag_filter", filters.tag.trim());
    if (filters.scope.trim()) params.set("scope_filter", filters.scope.trim());
    if (filters.namingOnly) params.set("naming_only", "true");
    if (filters.orphanOnly) params.set("orphan_only", "true");
    if (filters.minMembers !== "") params.set("min_members", String(Number(filters.minMembers) || 0));
    if (filters.maxMembers !== "") params.set("max_members", String(Number(filters.maxMembers) || 0));
    const query = params.toString();
    return query ? `?${query}` : "";
  }

  async function refreshAll() {
    setLoading(true);
    try {
      const query = new URLSearchParams(buildFilterQuery().replace(/^\?/, ""));
      if (matrixSearch.trim()) query.set("search", matrixSearch.trim());
      query.set("page", String(matrixPage));
      query.set("page_size", "20");
      query.set("sort_by", "display_name");
      query.set("sort_dir", "asc");

      const findingsQuery = new URLSearchParams(buildFilterQuery().replace(/^\?/, ""));
      if (riskSearch.trim()) findingsQuery.set("search", riskSearch.trim());
      findingsQuery.set("findings_page", String(findingsPage));
      findingsQuery.set("findings_page_size", "25");
      findingsQuery.set("findings_severity", riskSeverityFilter);
      const [matrixResult, riskResult, configResult] = await Promise.allSettled([
        fetch(`${apiEndpoint}/generate-matrix?${query.toString()}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        }),
        fetch(`${apiEndpoint}/compliance-check?${findingsQuery.toString()}`),
        fetch(`${apiEndpoint}/config`),
      ]);

      if (matrixResult.status === "fulfilled") {
        const matrixRes = matrixResult.value;
        if (!matrixRes.ok) {
          throw new Error(`Matrix API failed: ${matrixRes.status}`);
        }
        const matrixJson = await matrixRes.json();
        setMatrixData(normalizeMatrix(matrixJson));
        setMatrixSummary(matrixJson?.matrix?.summary || null);
        setTopRisks(matrixJson?.matrix?.summary?.top_risks || []);
      }

      if (riskResult.status === "fulfilled") {
        const riskRes = riskResult.value;
        if (riskRes.ok) {
          const riskJson = await riskRes.json();
          setRisksData(riskJson);
        } else {
          toast.error(`Risk API failed: ${riskRes.status}`);
        }
      } else {
        toast.error(`Risk API failed: ${riskResult.reason}`);
      }

      if (configResult.status === "fulfilled") {
        const configRes = configResult.value;
        if (configRes.ok) {
          const configJson = await configRes.json();
          setConfigSource(configJson?.source || "default");
        } else {
          toast.error(`Config API failed: ${configRes.status}`);
        }
      } else {
        toast.error(`Config API failed: ${configResult.reason}`);
      }
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  }

  async function refreshOverrideSuggestions() {
    setCatalogLoading(true);
    try {
      const res = await fetch(`${apiEndpoint}/policy/group-catalog/suggest-overrides?only_unmatched=true`);
      if (!res.ok) throw new Error(`Override suggestions API failed: ${res.status}`);
      const body = await res.json();
      setOverrideSuggestions(Array.isArray(body?.suggestions) ? body.suggestions : []);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setCatalogLoading(false);
    }
  }

  async function handleImportFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;

    setUploading(true);
    let startedAsync = false;
    try {
      const endpoint = `${apiEndpoint}/upload-config/async`;
      const formData = new FormData();
      formData.append("file", file);
      const res = await fetch(endpoint, {
        method: "POST",
        body: formData,
      });
      if (!res.ok) {
        let detail = `${res.status}`;
        try {
          const body = await res.json();
          detail = body?.detail || body?.message || detail;
        } catch {
          // ignore json parse failures
        }
        throw new Error(`Import failed: ${detail}`);
      }
      const payload = await res.json();
      if (payload?.job_id) {
        startedAsync = true;
        setImportJob({ job_id: payload.job_id, status: "queued" });
        toast.success("Import lance en arriere-plan");
      } else {
        toast.success(payload?.message || "Import AAD reussi");
        setImportJob(null);
        await refreshAll();
      }
    } catch (err) {
      setImportJob(null);
      toast.error(String(err));
    } finally {
      if (!startedAsync) {
        setUploading(false);
      }
    }
  }

  async function handleResetConfig() {
    setUploading(true);
    try {
      const res = await fetch(`${apiEndpoint}/config/reset`, { method: "POST" });
      if (!res.ok) throw new Error(`Reset failed: ${res.status}`);
      await refreshAll();
      toast.success("Configuration réinitialisée");
    } catch (err) {
      toast.error(String(err));
    } finally {
      setUploading(false);
    }
  }

  async function handleAzureSync() {
    setUploading(true);
    try {
      const res = await fetch(`${apiEndpoint}/aad/sync-azure?max_groups=500&workers=12`, {
        method: "POST",
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body?.detail || `Sync failed: ${res.status}`);
      toast.success(body?.message || "Azure sync done");
      await refreshAll();
    } catch (err) {
      toast.error(String(err));
    } finally {
      setUploading(false);
    }
  }

  async function applyOverrideSuggestion(suggestion) {
    const override = suggestion?.suggested_override;
    if (!override?.group_id) return;
    setApplyingOverrideId(override.group_id);
    try {
      const res = await fetch(`${apiEndpoint}/policy/group-catalog/overrides`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          overrides: [
            {
              group_id: override.group_id,
              profile: override.profile || "",
              tags: override.tags || {},
              group_type: override.group_type || "",
              domain: override.domain || "",
              env: override.env || "",
              criticality: override.criticality || "",
              max_scope_level: override.max_scope_level || "",
              notes: `Applied from dashboard suggestion for ${suggestion.display_name || override.group_id}`,
            },
          ],
        }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body?.detail || body?.message || `Override apply failed: ${res.status}`);
      toast.success(`Override applied for ${suggestion.display_name || override.group_id}`);
      await Promise.all([refreshAll(), refreshOverrideSuggestions()]);
    } catch (err) {
      toast.error(String(err));
    } finally {
      setApplyingOverrideId("");
    }
  }

  const totalGroups = matrixSummary?.total_groups_before_filter || matrixData.length;
  const totalMembers = useMemo(
    () => matrixData.reduce((sum, g) => sum + (g.members_count || 0), 0),
    [matrixData],
  );
  const highRiskCount = risksData?.high_risk_count || 0;
  const dataAccessEnabled = useMemo(
    () => matrixData.filter((g) => g.roles.some((r) => r.data_access)).length,
    [matrixData],
  );
  const orphanGroups = useMemo(
    () => matrixData.filter((g) => !g.owner).length,
    [matrixData],
  );

  const roleDistribution = useMemo(() => {
    const counts = new Map();
    for (const group of matrixData) {
      for (const role of group.roles) {
        if (!role.name) continue;
        counts.set(role.name, (counts.get(role.name) || 0) + 1);
      }
    }
    return Array.from(counts.entries()).map(([name, value]) => ({ name, value }));
  }, [matrixData]);

  const membersDistribution = useMemo(
    () => matrixData.map((g) => ({ name: g.display_name, members: g.members_count })),
    [matrixData],
  );

  const findingsData = Array.isArray(risksData?.findings) ? risksData.findings : [];
  const recommendationsData = Array.isArray(risksData?.recommendations) ? risksData.recommendations : [];
  const matrixPagination = matrixSummary?.pagination || null;
  const findingsPagination = risksData?.findings_pagination || null;
  const detailScope = risksData?.detail_scope || null;

  const filteredFindings = findingsData;
  const matrixVisible = matrixData;

  const filteredOverrideSuggestions = useMemo(() => {
    return overrideSuggestions.filter((suggestion) => {
      if (
        overrideConfidenceFilter !== "ALL" &&
        String(suggestion.confidence || "").toLowerCase() !== overrideConfidenceFilter.toLowerCase()
      ) {
        return false;
      }
      if (!overrideSearch.trim()) return true;
      const needle = overrideSearch.trim().toLowerCase();
      const override = suggestion.suggested_override || {};
      return [
        suggestion.display_name,
        suggestion.group_id,
        suggestion.current_match_source,
        override.profile,
        override.domain,
        override.group_type,
        ...(suggestion.roles || []),
      ].some((value) => String(value || "").toLowerCase().includes(needle));
    });
  }, [overrideSuggestions, overrideSearch, overrideConfidenceFilter]);

  useEffect(() => {
    setMatrixPage(1);
  }, [matrixSearch, filters.owner, filters.tag, filters.scope, filters.namingOnly, filters.orphanOnly, filters.minMembers, filters.maxMembers]);

  useEffect(() => {
    setFindingsPage(1);
  }, [riskSearch, riskSeverityFilter, filters.owner, filters.tag, filters.scope, filters.namingOnly, filters.orphanOnly, filters.minMembers, filters.maxMembers]);

  useEffect(() => {
    void refreshAll();
  }, [matrixPage, findingsPage, matrixSearch, riskSearch, riskSeverityFilter, filters.owner, filters.tag, filters.scope, filters.namingOnly, filters.orphanOnly, filters.minMembers, filters.maxMembers]);

  return (
    <div className="dashboard-shell min-h-screen text-slate-900">
      <Toaster position="top-right" />

      <header className="sticky top-0 z-10 border-b border-white/30 bg-white/65 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-4 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:gap-8">
            <h1 className="flex items-center gap-3 text-xl font-bold text-slate-900">
              <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[linear-gradient(135deg,#153a5b,#0f8b8d)] text-white shadow-lg shadow-cyan-900/20">
                <Shield className="h-5 w-5" />
              </span>
              RBAC Governance Dashboard
            </h1>
            <nav className="glass-panel inline-flex flex-wrap items-center gap-2 rounded-2xl p-1.5">
              <button
                onClick={() => navigate("dashboard")}
                className={`inline-flex min-h-11 min-w-[190px] flex-1 items-center justify-center gap-2 rounded-xl px-5 py-2.5 text-base font-medium ${
                  route === "dashboard" ? "bg-slate-900 text-white shadow-sm" : "text-slate-600 hover:bg-white hover:text-slate-900"
                }`}
              >
                <LayoutDashboard className="h-4 w-4" />
                Dashboard
              </button>
              <button
                onClick={() => navigate("policy")}
                className={`inline-flex min-h-11 min-w-[190px] flex-1 items-center justify-center gap-2 rounded-xl px-5 py-2.5 text-base font-medium ${
                  route === "policy" ? "bg-slate-900 text-white shadow-sm" : "text-slate-600 hover:bg-white hover:text-slate-900"
                }`}
              >
                <Settings className="h-4 w-4" />
                Policy Studio
              </button>
            </nav>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="rounded-full bg-slate-900 px-3 py-1.5 text-xs font-semibold tracking-wide text-white">
              Source: {configSource}
            </span>
            {importJob?.job_id ? (
              <span className={`rounded-full px-3 py-1.5 text-xs font-semibold tracking-wide ${
                importJob.status === "failed"
                  ? "bg-red-100 text-red-700"
                  : importJob.status === "completed"
                    ? "bg-emerald-100 text-emerald-700"
                    : "bg-amber-100 text-amber-800"
              }`}>
                Import: {importJob.status}{importJob.total_groups ? ` (${importJob.total_groups} groupes)` : ""}
              </span>
            ) : null}
            {route === "dashboard" ? (
              <>
            <label className={`inline-flex min-h-11 min-w-[170px] cursor-pointer items-center justify-center ${CONTROL_CLASS}`}>
              {uploading ? "Import..." : "Importer AAD (JSON/CSV)"}
              <input
                type="file"
                accept=".json,.csv,text/csv,application/json"
                className="hidden"
                onChange={(e) => void handleImportFile(e)}
                disabled={uploading}
              />
            </label>
            <button
              onClick={() => void refreshAll()}
              className={`${CONTROL_CLASS} min-w-[120px]`}
            >
              Rafraichir
            </button>
            <button
              onClick={() => void handleAzureSync()}
              className={`${CONTROL_CLASS} min-w-[120px]`}
              disabled={uploading}
            >
              Sync Azure
            </button>
            <button
              onClick={() => void handleResetConfig()}
              className={`${CONTROL_CLASS} min-w-[120px]`}
              disabled={uploading}
            >
              Reset config
            </button>
            <a
              href={`${apiEndpoint}/generate-matrix/json`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex min-h-11 min-w-[140px] items-center justify-center gap-2 rounded-lg bg-[linear-gradient(135deg,#153a5b,#0f8b8d)] px-4 py-2 text-sm font-medium text-white transition hover:brightness-105"
            >
              <Download className="h-4 w-4" /> Export JSON
            </a>
              </>
            ) : null}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {route === "policy" ? (
          <PolicyStudio apiEndpoint={apiEndpoint} />
        ) : (
          <>
        <Card title="Governance filters">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <input
              className={INPUT_CLASS}
              placeholder="Owner contains (ex: secops@)"
              value={filters.owner}
              onChange={(e) => setFilters((f) => ({ ...f, owner: e.target.value }))}
            />
            <input
              className={INPUT_CLASS}
              placeholder="Tag (ex: env=prod or criticality)"
              value={filters.tag}
              onChange={(e) => setFilters((f) => ({ ...f, tag: e.target.value }))}
            />
            <input
              className={INPUT_CLASS}
              placeholder="Scope contains (ex: /subscriptions/sub-prod)"
              value={filters.scope}
              onChange={(e) => setFilters((f) => ({ ...f, scope: e.target.value }))}
            />
            <div className="grid grid-cols-2 gap-2">
              <input
                className={INPUT_CLASS}
                placeholder="Min members"
                value={filters.minMembers}
                onChange={(e) => setFilters((f) => ({ ...f, minMembers: e.target.value }))}
              />
              <input
                className={INPUT_CLASS}
                placeholder="Max members"
                value={filters.maxMembers}
                onChange={(e) => setFilters((f) => ({ ...f, maxMembers: e.target.value }))}
              />
            </div>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={filters.namingOnly}
                onChange={(e) => setFilters((f) => ({ ...f, namingOnly: e.target.checked }))}
              />
              Naming compliant only
            </label>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={filters.orphanOnly}
                onChange={(e) => setFilters((f) => ({ ...f, orphanOnly: e.target.checked }))}
              />
              Orphan groups only
            </label>
            <button
              onClick={() => void refreshAll()}
              className="min-h-11 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700"
            >
              Apply filters
            </button>
            <button
              onClick={() => {
                setFilters({
                  owner: "",
                  tag: "",
                  scope: "",
                  namingOnly: false,
                  orphanOnly: false,
                  minMembers: "",
                  maxMembers: "",
                });
                setTimeout(() => void refreshAll(), 0);
              }}
              className={`${CONTROL_CLASS} px-4`}
            >
              Clear
            </button>
          </div>
        </Card>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
          <StatCard title="Total groups" value={totalGroups} icon={Users} />
          <StatCard title="Total members" value={totalMembers} icon={Server} />
          <StatCard title="Data access enabled" value={dataAccessEnabled} icon={Activity} />
          <StatCard title="High risk" value={highRiskCount} icon={Shield} danger={highRiskCount > 0} />
          <StatCard title="Orphan groups" value={orphanGroups} icon={Users} danger={orphanGroups > 0} />
        </section>

        <section className="glass-panel grid grid-cols-2 gap-2 rounded-2xl p-2 lg:grid-cols-4">
          {[
            ["overview", "Overview"],
            ["findings", `Findings (${risksData?.findings_total || 0})`],
            ["matrix", `Matrix (${matrixPagination?.total || matrixVisible.length})`],
            ["overrides", `Overrides (${overrideSuggestions.length})`],
          ].map(([key, label]) => (
            <button
              key={key}
              onClick={() => setDashboardTab(key)}
              className={`${TAB_CLASS} w-full ${
                dashboardTab === key ? "bg-[linear-gradient(135deg,#153a5b,#0f8b8d)] text-white shadow-md shadow-cyan-900/15" : "bg-white/70 text-slate-600 hover:bg-white hover:text-slate-900"
              }`}
            >
              {label}
            </button>
          ))}
        </section>

        {dashboardTab === "overview" ? (
        <>
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card title="Role distribution">
            <div className="h-72">
              {roleDistribution.length === 0 ? (
                <div className="flex h-full items-center justify-center text-sm text-slate-500">
                  Aucun rôle mappé pour les groupes chargés.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={roleDistribution} dataKey="value" nameKey="name" outerRadius={95} label>
                      {roleDistribution.map((_, idx) => (
                        <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>

          <Card title="Members by group">
            <div className="h-72">
              {membersDistribution.length === 0 ? (
                <div className="flex h-full items-center justify-center text-sm text-slate-500">
                  Aucun groupe chargé.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={membersDistribution}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" hide={membersDistribution.length > 8} />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="members" radius={[6, 6, 0, 0]}>
                      {membersDistribution.map((_, idx) => (
                        <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>
        </section>
        <Card title="Top governance risks">
          {topRisks.length === 0 ? (
            <p className="text-sm text-slate-500">Aucun risque majeur selon les filtres courants.</p>
          ) : (
            <div className="space-y-2">
              {topRisks.map((risk) => (
                <div key={risk.group_id} className="glass-panel-strong rounded-xl px-4 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-semibold text-slate-800">
                      {risk.display_name} ({risk.group_id})
                    </div>
                    <div className="text-sm font-bold text-red-700">Score {risk.score} - {risk.level}</div>
                  </div>
                  <div className="mt-1 text-sm text-slate-600">
                    {(risk.reasons || []).join(" | ")}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
        </>
        ) : null}

        {dashboardTab === "findings" ? (
        <Card title="Compliance risks">
          {!risksData ? (
            <p className="text-sm text-slate-500">Aucune donnee de risque chargee.</p>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_180px]">
                <label className="relative">
                  <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-400" />
                  <input
                    className="min-h-11 w-full rounded-lg border border-slate-300 pl-9 pr-3 py-2 text-sm"
                    placeholder="Rechercher un finding, groupe, règle..."
                    value={riskSearch}
                    onChange={(e) => setRiskSearch(e.target.value)}
                  />
                </label>
                <select
                  className={`${INPUT_CLASS} w-full`}
                  value={riskSeverityFilter}
                  onChange={(e) => setRiskSeverityFilter(e.target.value)}
                >
                  <option value="ALL">Toutes severites</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="INFO">Info</option>
                </select>
              </div>

              <div className="text-xs text-slate-500">
                Findings visibles: {filteredFindings.length} / {risksData?.findings_total || filteredFindings.length} | Recommandations: {recommendationsData.length}
              </div>

              {detailScope?.limited ? (
                <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                  Analyse detaillee limitee a {detailScope.detailed_groups_analyzed} groupes sur {risksData?.total_groups_scanned || detailScope.detailed_groups_analyzed} pour garder l'interface exploitable. Utilise les filtres ou la recherche pour cibler un sous-ensemble plus precis.
                </div>
              ) : null}

              {filteredFindings.length > 0 ? (
                <div className="space-y-2">
                  {filteredFindings.map((finding, i) => (
                    <div
                      key={`${finding.group_id}-${finding.rule_id}-${i}`}
                      className="glass-panel-strong rounded-xl px-4 py-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded-full px-2 py-1 text-xs font-semibold ${severityTone(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <span className={`rounded-full px-2 py-1 text-xs font-semibold ${confidenceTone(finding.confidence)}`}>
                          {finding.confidence || "n/a"}
                        </span>
                        <span className="text-sm font-semibold text-slate-800">{finding.title}</span>
                      </div>
                      <div className="mt-2 text-sm text-slate-600">{finding.description}</div>
                      <div className="mt-2 text-sm text-slate-700">
                        Action: <span className="font-medium">{finding.recommendation}</span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2 text-xs text-slate-500">
                        <span>{finding.group} ({finding.group_id})</span>
                        {finding.rule_id ? <span>Rule: {finding.rule_id}</span> : null}
                        {finding.basis ? <span>Basis: {finding.basis}</span> : null}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-500">Aucun finding ne correspond aux filtres.</p>
              )}

              {findingsPagination ? (
                <div className="flex items-center justify-end gap-2">
                  <button
                    onClick={() => setFindingsPage((page) => Math.max(1, page - 1))}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100 disabled:opacity-50"
                    disabled={!findingsPagination.has_prev}
                  >
                    <ChevronLeft className="h-4 w-4" />
                    Prev
                  </button>
                  <div className="text-sm text-slate-500">
                    Page {findingsPagination.page} / {findingsPagination.total_pages}
                  </div>
                  <button
                    onClick={() => setFindingsPage((page) => page + 1)}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100 disabled:opacity-50"
                    disabled={!findingsPagination.has_next}
                  >
                    Next
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              ) : null}

              <div className="glass-panel rounded-2xl p-4">
                <div className="mb-3 text-sm font-semibold text-slate-800">Recommended actions</div>
                {recommendationsData.length > 0 ? (
                  <div className="space-y-2">
                    {recommendationsData.slice(0, 8).map((item, idx) => (
                      <div key={`${item.group_id}-${idx}`} className="rounded-lg bg-white px-4 py-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`rounded-full px-2 py-1 text-xs font-semibold ${severityTone(item.risk_level)}`}>
                            {item.risk_level}
                          </span>
                          <span className={`rounded-full px-2 py-1 text-xs font-semibold ${confidenceTone(item.confidence)}`}>
                            {item.confidence}
                          </span>
                          <span className="text-sm font-semibold text-slate-800">{item.group}</span>
                        </div>
                        <div className="mt-2 text-sm text-slate-700">{item.recommended_action}</div>
                        <div className="mt-1 text-xs text-slate-500">{item.why}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-slate-500">Aucune recommandation structuree.</div>
                )}
              </div>
            </div>
          )}
        </Card>
        ) : null}

        {dashboardTab === "overrides" ? (
        <Card title="Governance catalog overrides">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <p className="text-sm text-slate-600">
                Valide les suggestions pour sortir des heuristiques et fixer un profil explicite par groupe.
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Suggestions ouvertes: {overrideSuggestions.length}
              </p>
            </div>
            <button
              onClick={() => void refreshOverrideSuggestions()}
              className={`${CONTROL_CLASS} min-w-[170px]`}
              disabled={catalogLoading}
            >
              {catalogLoading ? "Refresh..." : "Refresh suggestions"}
            </button>
          </div>

          <div className="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-[1fr_180px]">
            <label className="relative">
              <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-400" />
              <input
                className="min-h-11 w-full rounded-lg border border-slate-300 pl-9 pr-3 py-2 text-sm"
                placeholder="Rechercher un groupe, profil ou domaine..."
                value={overrideSearch}
                onChange={(e) => setOverrideSearch(e.target.value)}
              />
            </label>
            <select
              className={`${INPUT_CLASS} w-full`}
              value={overrideConfidenceFilter}
              onChange={(e) => setOverrideConfidenceFilter(e.target.value)}
            >
              <option value="ALL">Toutes confiances</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {filteredOverrideSuggestions.length === 0 ? (
            <p className="text-sm text-slate-500">Aucune suggestion d'override ouverte.</p>
          ) : (
            <div className="space-y-3">
              {filteredOverrideSuggestions.slice(0, 20).map((suggestion) => {
                const override = suggestion.suggested_override || {};
                return (
                  <div
                    key={suggestion.group_id}
                    className="glass-panel-strong rounded-2xl p-4"
                  >
                    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                      <div className="space-y-2">
                        <div>
                          <div className="text-sm font-semibold text-slate-900">
                            {suggestion.display_name} ({suggestion.group_id})
                          </div>
                          <div className="mt-1 flex flex-wrap gap-2 text-xs">
                            <span className="rounded-full bg-white px-2 py-1 text-slate-600">
                              Current: {suggestion.current_match_source || "unmatched"}
                            </span>
                            <span className="rounded-full bg-indigo-100 px-2 py-1 font-medium text-indigo-700">
                              Proposed profile: {override.profile || "n/a"}
                            </span>
                            <span className={`rounded-full px-2 py-1 font-medium ${confidenceTone(suggestion.confidence)}`}>
                              Confidence: {suggestion.confidence || "low"}
                            </span>
                          </div>
                        </div>

                        <div className="flex flex-wrap gap-2 text-xs text-slate-600">
                          <span className="rounded-full bg-white px-2 py-1">
                            group_type: {override.group_type || "?"}
                          </span>
                          <span className="rounded-full bg-white px-2 py-1">
                            domain: {override.domain || "?"}
                          </span>
                          <span className="rounded-full bg-white px-2 py-1">
                            env: {override.env || "?"}
                          </span>
                          <span className="rounded-full bg-white px-2 py-1">
                            criticality: {override.criticality || "?"}
                          </span>
                          <span className="rounded-full bg-white px-2 py-1">
                            max_scope: {override.max_scope_level || "?"}
                          </span>
                        </div>

                        <div className="text-xs text-slate-500">
                          Roles: {(suggestion.roles || []).join(", ") || "none"}
                        </div>
                        <div className="text-xs text-slate-500">
                          Reasons: {(suggestion.reasons || []).join(" | ") || "No explanation"}
                        </div>
                        {override.tags && Object.keys(override.tags).length > 0 ? (
                          <div className="flex flex-wrap gap-2">
                            {Object.entries(override.tags).map(([key, value]) => (
                              <span
                                key={`${suggestion.group_id}-${key}`}
                                className="rounded-full bg-emerald-100 px-2 py-1 text-xs font-medium text-emerald-700"
                              >
                                {key}={String(value)}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </div>

                      <button
                        onClick={() => void applyOverrideSuggestion(suggestion)}
                        className="inline-flex min-h-11 min-w-[150px] items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-400"
                        disabled={applyingOverrideId === suggestion.group_id}
                      >
                        {applyingOverrideId === suggestion.group_id ? (
                          <>Applying...</>
                        ) : (
                          <>
                            <Check className="h-4 w-4" />
                            Apply override
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                );
              })}
              {filteredOverrideSuggestions.length > 20 ? (
                <div className="text-xs text-slate-500">
                  {filteredOverrideSuggestions.length - 20} suggestions masquees. Affine la recherche pour continuer.
                </div>
              ) : null}
            </div>
          )}
        </Card>
        ) : null}

        {dashboardTab === "matrix" ? (
        <Card title="Access matrix">
          {loading ? (
            <p className="text-sm text-slate-500">Chargement...</p>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <label className="relative lg:w-96">
                  <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-400" />
                  <input
                    className="min-h-11 w-full rounded-lg border border-slate-300 pl-9 pr-3 py-2 text-sm"
                    placeholder="Rechercher groupe, owner, scope ou role..."
                    value={matrixSearch}
                    onChange={(e) => setMatrixSearch(e.target.value)}
                  />
                </label>
                <div className="text-sm text-slate-500">
                  {matrixPagination?.total || matrixVisible.length} groupe(s) | page {matrixPagination?.page || 1} / {matrixPagination?.total_pages || 1}
                </div>
              </div>

              <div className="overflow-x-auto">
              <table className="dashboard-table min-w-full border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                    <th className="px-3 py-2">Group</th>
                    <th className="px-3 py-2">Owner</th>
                    <th className="px-3 py-2">Members</th>
                    <th className="px-3 py-2">Roles</th>
                    <th className="px-3 py-2 text-center">Data Access</th>
                  </tr>
                </thead>
                <tbody>
                  {matrixVisible.map((group) => (
                    <tr key={group.group_id} className="border-b border-slate-100 align-top">
                      <td className="px-3 py-3">
                        <div className="font-medium text-indigo-700">{group.display_name}</div>
                        <div className="text-xs text-slate-500">{group.group_id}</div>
                      </td>
                      <td className="px-3 py-3 text-sm">
                        {group.owner ? (
                          <span className="text-slate-700">{group.owner}</span>
                        ) : (
                          <span className="rounded-full bg-amber-100 px-2 py-1 text-xs font-medium text-amber-700">
                            No owner
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-3 text-sm">{group.members_count}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-2">
                          {group.roles.map((role, idx) => (
                            <span
                              key={`${group.group_id}-${idx}`}
                              className={`rounded-full px-2.5 py-1 text-xs font-medium ${
                                role.security_admin
                                  ? "bg-red-100 text-red-700"
                                  : role.data_access
                                    ? "bg-emerald-100 text-emerald-700"
                                    : "bg-slate-100 text-slate-700"
                              }`}
                            >
                              {role.name}
                            </span>
                          ))}
                          {group.roles.length === 0 && (
                            <span className="rounded-full bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-700">
                              No role mapped
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3 text-center">
                        {group.roles.some((r) => r.data_access) ? (
                          <CheckCircle2 className="mx-auto h-5 w-5 text-emerald-600" />
                        ) : (
                          <XCircle className="mx-auto h-5 w-5 text-slate-300" />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>

              <div className="flex items-center justify-end gap-2">
                <button
                  onClick={() => setMatrixPage((page) => Math.max(1, page - 1))}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100 disabled:opacity-50"
                  disabled={!matrixPagination?.has_prev}
                >
                  <ChevronLeft className="h-4 w-4" />
                  Prev
                </button>
                <button
                  onClick={() => setMatrixPage((page) => page + 1)}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100 disabled:opacity-50"
                  disabled={!matrixPagination?.has_next}
                >
                  Next
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </Card>
        ) : null}
          </>
        )}
      </main>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, danger = false }) {
  return (
    <div className="stat-panel rounded-2xl p-4">
      <div className="mb-2 flex items-center justify-between">
        <p className="text-xs uppercase tracking-wide text-slate-500">{title}</p>
        <span className={`flex h-9 w-9 items-center justify-center rounded-xl ${danger ? "bg-red-100 text-red-600" : "bg-cyan-50 text-cyan-800"}`}>
          <Icon className="h-4 w-4" />
        </span>
      </div>
      <div className={`text-3xl font-bold ${danger ? "text-red-700" : "text-slate-900"}`}>{value}</div>
    </div>
  );
}

function Card({ title, children }) {
  return (
    <section className="glass-panel rounded-3xl p-5">
      <h2 className="section-title mb-4 flex items-center gap-2 text-lg font-semibold text-slate-900">
        <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-cyan-50 text-cyan-800">
          <Wand2 className="h-4 w-4" />
        </span>
        {title}
      </h2>
      {children}
    </section>
  );
}

function PolicyStudio({ apiEndpoint }) {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [version, setVersion] = useState("2.0");
  const [requirementsText, setRequirementsText] = useState("{}");
  const [allowedRolesText, setAllowedRolesText] = useState("{}");
  const [forbiddenRulesText, setForbiddenRulesText] = useState("[]");
  const [accessControlText, setAccessControlText] = useState("{}");
  const [profiles, setProfiles] = useState({});
  const [matchers, setMatchers] = useState([]);
  const [overrides, setOverrides] = useState({});

  useEffect(() => {
    void loadPolicyStudio();
  }, []);

  async function loadPolicyStudio() {
    setLoading(true);
    try {
      const res = await fetch(`${apiEndpoint}/policy`);
      if (!res.ok) throw new Error(`Policy API failed: ${res.status}`);
      const body = await res.json();
      const policy = body?.policy || {};
      setVersion(String(policy?.version || "2.0"));
      setRequirementsText(prettyJson(policy?.requirements || {}));
      setAllowedRolesText(prettyJson(policy?.allowed_roles_by_group_type || {}));
      setForbiddenRulesText(prettyJson(policy?.forbidden_rules || []));
      setProfiles(policy?.governance_profiles || {});
      setMatchers(Array.isArray(policy?.group_catalog?.matchers) ? policy.group_catalog.matchers : []);
      setOverrides(policy?.group_catalog?.overrides || {});
      setAccessControlText(prettyJson(policy?.access_control || {}));
    } catch (err) {
      toast.error(String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleSavePolicy() {
    const parsedRequirements = parseJsonField("requirements", requirementsText);
    const parsedAllowedRoles = parseJsonField("allowed_roles_by_group_type", allowedRolesText);
    const parsedForbiddenRules = parseJsonField("forbidden_rules", forbiddenRulesText);
    const parsedAccessControl = parseJsonField("access_control", accessControlText);

    const parsed = [
      parsedRequirements,
      parsedAllowedRoles,
      parsedForbiddenRules,
      parsedAccessControl,
    ];
    const failed = parsed.find((item) => !item.ok);
    if (failed) {
      toast.error(failed.error);
      return;
    }

    setSaving(true);
    try {
      const payload = {
        version,
        requirements: parsedRequirements.value,
        allowed_roles_by_group_type: parsedAllowedRoles.value,
        forbidden_rules: parsedForbiddenRules.value,
        governance_profiles: profiles,
        group_catalog: {
          matchers,
          overrides,
        },
        access_control: parsedAccessControl.value,
      };

      const res = await fetch(`${apiEndpoint}/policy`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body?.detail || body?.message || `Policy save failed: ${res.status}`);
      toast.success("Policy updated");
      await loadPolicyStudio();
    } catch (err) {
      toast.error(String(err));
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <Card title="Policy Studio">
        <p className="text-sm text-slate-500">Chargement de la policy...</p>
      </Card>
    );
  }

  return (
    <>
      <Card title="Policy Studio">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-1">
            <p className="text-sm text-slate-600">
              Edite les blocs structurants de la gouvernance sans passer par le YAML.
            </p>
            <p className="text-xs text-slate-500">
              Les champs sont sauvegardés via l'API `/policy` et restent compatibles avec le moteur de recommandations.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <label className="text-sm text-slate-600">
              Version
              <input
                className="ml-2 rounded-lg border border-slate-300 px-3 py-2 text-sm"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
              />
            </label>
            <button
              onClick={() => void loadPolicyStudio()}
              className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100"
              disabled={saving}
            >
              Reload
            </button>
            <button
              onClick={() => void handleSavePolicy()}
              className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-400"
              disabled={saving}
            >
              <Save className="h-4 w-4" />
              {saving ? "Saving..." : "Save policy"}
            </button>
          </div>
        </div>
      </Card>

      <section className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <JsonEditorCard
          title="Requirements"
          description="Règles globales: owner obligatoire, tags requis, fréquence de revue."
          value={requirementsText}
          onChange={setRequirementsText}
        />
        <JsonEditorCard
          title="Allowed Roles by Group Type"
          description="Matrice de rôles autorisés pour `USR`, `ADM`, `SEC`."
          value={allowedRolesText}
          onChange={setAllowedRolesText}
        />
        <JsonEditorCard
          title="Forbidden Rules"
          description="Interdictions et exceptions gouvernance."
          value={forbiddenRulesText}
          onChange={setForbiddenRulesText}
        />
      </section>

      <VisualProfilesEditor profiles={profiles} onChange={setProfiles} />
      <VisualMatchersEditor matchers={matchers} onChange={setMatchers} />
      <VisualOverridesEditor overrides={overrides} onChange={setOverrides} />

      <JsonEditorCard
        title="Access Control"
        description="Configuration des groupes admin/user pour l'accès à l'outil."
        value={accessControlText}
        onChange={setAccessControlText}
      />
    </>
  );
}

function JsonEditorCard({ title, description, value, onChange }) {
  return (
    <Card title={title}>
      <p className="mb-3 text-sm text-slate-600">{description}</p>
      <textarea
        className="min-h-[260px] w-full rounded-xl border border-slate-300 bg-slate-950 p-4 font-mono text-sm text-slate-100 outline-none ring-0"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        spellCheck={false}
      />
    </Card>
  );
}

function VisualProfilesEditor({ profiles, onChange }) {
  const entries = Object.entries(profiles || {});

  function addProfile() {
    const nextKey = `new_profile_${entries.length + 1}`;
    onChange({
      ...profiles,
      [nextKey]: {
        group_type: "USR",
        domain: "",
        env: "dev",
        criticality: "low",
        max_scope_level: "resource_group",
        recommended_controls: [],
      },
    });
  }

  return (
    <Card title="Governance Profiles">
      <div className="mb-4 flex items-center justify-between">
        <p className="text-sm text-slate-600">Profils explicites utilisés par le moteur de recommandations.</p>
        <button onClick={addProfile} className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white hover:bg-slate-800">
          <Plus className="h-4 w-4" />
          Add profile
        </button>
      </div>
      <div className="space-y-4">
        {entries.map(([profileKey, profile]) => (
          <div key={profileKey} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <input
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium"
                value={profileKey}
                onChange={(e) => onChange(updateObjectKey(profiles, profileKey, e.target.value || profileKey, profile))}
              />
              <button
                onClick={() => {
                  const next = { ...profiles };
                  delete next[profileKey];
                  onChange(next);
                }}
                className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50"
              >
                <Trash2 className="h-4 w-4" />
                Remove
              </button>
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
              <LabeledField label="Group Type" value={profile.group_type || ""} onChange={(value) => onChange({ ...profiles, [profileKey]: { ...profile, group_type: value } })} />
              <LabeledField label="Domain" value={profile.domain || ""} onChange={(value) => onChange({ ...profiles, [profileKey]: { ...profile, domain: value } })} />
              <LabeledField label="Env" value={profile.env || ""} onChange={(value) => onChange({ ...profiles, [profileKey]: { ...profile, env: value } })} />
              <LabeledField label="Criticality" value={profile.criticality || ""} onChange={(value) => onChange({ ...profiles, [profileKey]: { ...profile, criticality: value } })} />
              <LabeledField label="Max Scope" value={profile.max_scope_level || ""} onChange={(value) => onChange({ ...profiles, [profileKey]: { ...profile, max_scope_level: value } })} />
            </div>
            <StringListEditor
              label="Recommended Controls"
              values={Array.isArray(profile.recommended_controls) ? profile.recommended_controls : []}
              onChange={(values) => onChange({ ...profiles, [profileKey]: { ...profile, recommended_controls: values } })}
            />
          </div>
        ))}
        {entries.length === 0 ? <div className="text-sm text-slate-500">No profiles defined.</div> : null}
      </div>
    </Card>
  );
}

function VisualMatchersEditor({ matchers, onChange }) {
  function updateMatcher(index, updater) {
    onChange(matchers.map((item, idx) => (idx === index ? updater(item) : item)));
  }

  return (
    <Card title="Catalog Matchers">
      <div className="mb-4 flex items-center justify-between">
        <p className="text-sm text-slate-600">Règles de matching automatique entre groupes et profils.</p>
        <button
          onClick={() => onChange([...(matchers || []), { id: `matcher-${(matchers || []).length + 1}`, match: {}, profile: "", tags: {} }])}
          className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white hover:bg-slate-800"
        >
          <Plus className="h-4 w-4" />
          Add matcher
        </button>
      </div>
      <div className="space-y-4">
        {(matchers || []).map((matcher, index) => (
          <div key={`${matcher.id || "matcher"}-${index}`} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <input
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium"
                value={matcher.id || ""}
                onChange={(e) => updateMatcher(index, (item) => ({ ...item, id: e.target.value }))}
              />
              <button
                onClick={() => onChange(matchers.filter((_, idx) => idx !== index))}
                className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50"
              >
                <Trash2 className="h-4 w-4" />
                Remove
              </button>
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              <LabeledField label="Profile" value={matcher.profile || ""} onChange={(value) => updateMatcher(index, (item) => ({ ...item, profile: value }))} />
              <LabeledField label="Display Name Regex" value={matcher.match?.display_name_regex || ""} onChange={(value) => updateMatcher(index, (item) => ({ ...item, match: { ...(item.match || {}), display_name_regex: value } }))} />
              <LabeledField label="Group ID Regex" value={matcher.match?.group_id_regex || ""} onChange={(value) => updateMatcher(index, (item) => ({ ...item, match: { ...(item.match || {}), group_id_regex: value } }))} />
            </div>
            <StringListEditor
              label="Role Any"
              values={Array.isArray(matcher.match?.role_any) ? matcher.match.role_any : []}
              onChange={(values) => updateMatcher(index, (item) => ({ ...item, match: { ...(item.match || {}), role_any: values } }))}
            />
            <KeyValueEditor
              label="Injected Tags"
              value={matcher.tags || {}}
              onChange={(value) => updateMatcher(index, (item) => ({ ...item, tags: value }))}
            />
          </div>
        ))}
        {(matchers || []).length === 0 ? <div className="text-sm text-slate-500">No matchers defined.</div> : null}
      </div>
    </Card>
  );
}

function VisualOverridesEditor({ overrides, onChange }) {
  const entries = Object.entries(overrides || {});

  function updateOverride(groupId, nextValue) {
    onChange({ ...overrides, [groupId]: nextValue });
  }

  function removeOverride(groupId) {
    const next = { ...overrides };
    delete next[groupId];
    onChange(next);
  }

  function addOverride() {
    const nextKey = `GROUP_ID_${entries.length + 1}`;
    onChange({
      ...overrides,
      [nextKey]: {
        profile: "",
        tags: {},
        group_type: "",
        domain: "",
        env: "",
        criticality: "",
        max_scope_level: "",
        notes: "",
      },
    });
  }

  return (
    <Card title="Catalog Overrides">
      <div className="mb-4 flex items-center justify-between">
        <p className="text-sm text-slate-600">Overrides explicites par `group_id` pour éliminer l'ambiguïté.</p>
        <button onClick={addOverride} className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-3 py-2 text-sm text-white hover:bg-slate-800">
          <Plus className="h-4 w-4" />
          Add override
        </button>
      </div>
      <div className="space-y-4">
        {entries.map(([groupId, override]) => (
          <div key={groupId} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="mb-3 flex items-center justify-between gap-3">
              <input
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium"
                value={groupId}
                onChange={(e) => onChange(updateObjectKey(overrides, groupId, e.target.value || groupId, override))}
              />
              <button
                onClick={() => removeOverride(groupId)}
                className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50"
              >
                <Trash2 className="h-4 w-4" />
                Remove
              </button>
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-5">
              <LabeledField label="Profile" value={override.profile || ""} onChange={(value) => updateOverride(groupId, { ...override, profile: value })} />
              <LabeledField label="Group Type" value={override.group_type || ""} onChange={(value) => updateOverride(groupId, { ...override, group_type: value })} />
              <LabeledField label="Domain" value={override.domain || ""} onChange={(value) => updateOverride(groupId, { ...override, domain: value })} />
              <LabeledField label="Env" value={override.env || ""} onChange={(value) => updateOverride(groupId, { ...override, env: value })} />
              <LabeledField label="Criticality" value={override.criticality || ""} onChange={(value) => updateOverride(groupId, { ...override, criticality: value })} />
            </div>
            <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <LabeledField label="Max Scope" value={override.max_scope_level || ""} onChange={(value) => updateOverride(groupId, { ...override, max_scope_level: value })} />
              <LabeledField label="Notes" value={override.notes || ""} onChange={(value) => updateOverride(groupId, { ...override, notes: value })} />
            </div>
            <KeyValueEditor
              label="Tags"
              value={override.tags || {}}
              onChange={(value) => updateOverride(groupId, { ...override, tags: value })}
            />
          </div>
        ))}
        {entries.length === 0 ? <div className="text-sm text-slate-500">No overrides defined.</div> : null}
      </div>
    </Card>
  );
}

function LabeledField({ label, value, onChange }) {
  return (
    <label className="text-xs font-medium uppercase tracking-wide text-slate-500">
      {label}
      <input
        className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal text-slate-900"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  );
}

function StringListEditor({ label, values, onChange }) {
  return (
    <div className="mt-3">
      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="space-y-2">
        {values.map((value, index) => (
          <div key={`${label}-${index}`} className="flex items-center gap-2">
            <input
              className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm"
              value={value}
              onChange={(e) => onChange(values.map((item, idx) => (idx === index ? e.target.value : item)).filter(Boolean))}
            />
            <button
              onClick={() => onChange(values.filter((_, idx) => idx !== index))}
              className="rounded-lg border border-red-200 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50"
            >
              Remove
            </button>
          </div>
        ))}
        <button
          onClick={() => onChange([...(values || []), ""])}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100"
        >
          Add value
        </button>
      </div>
    </div>
  );
}

function KeyValueEditor({ label, value, onChange }) {
  const entries = Object.entries(value || {});
  return (
    <div className="mt-3">
      <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="space-y-2">
        {entries.map(([key, currentValue], index) => (
          <div key={`${label}-${index}`} className="grid grid-cols-[1fr_1fr_auto] gap-2">
            <input
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              value={key}
              onChange={(e) => onChange(updateObjectKey(value, key, e.target.value || key, currentValue))}
            />
            <input
              className="rounded-lg border border-slate-300 px-3 py-2 text-sm"
              value={currentValue}
              onChange={(e) => onChange({ ...value, [key]: e.target.value })}
            />
            <button
              onClick={() => {
                const next = { ...(value || {}) };
                delete next[key];
                onChange(next);
              }}
              className="rounded-lg border border-red-200 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50"
            >
              Remove
            </button>
          </div>
        ))}
        <button
          onClick={() => onChange({ ...(value || {}), [`key_${entries.length + 1}`]: "" })}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm hover:bg-slate-100"
        >
          Add tag
        </button>
      </div>
    </div>
  );
}
