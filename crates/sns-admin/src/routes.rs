//! Admin API route table (spec §31–33). Declared as data so the surface is reviewable now;
//! handler bodies land with the HTTP server. All routes require an authenticated session
//! except `POST /api/login`. All are read-only over collected data except login/logout and
//! authorized config changes (which append to configuration_history + audit_log).

pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
    pub summary: &'static str,
}

pub const ROUTES: &[Route] = &[
    Route { method: "POST", path: "/api/login", summary: "Argon2id auth → session cookie" },
    Route { method: "POST", path: "/api/logout", summary: "Invalidate session" },
    // Dashboard / device (spec §32)
    Route { method: "GET", path: "/api/device", summary: "Device dashboard: id, name, ip, storage, last event/screenshot" },
    Route { method: "GET", path: "/api/health", summary: "Health snapshot (spec §26)" },
    // Timeline + collectors (spec §33)
    Route { method: "GET", path: "/api/timeline", summary: "Activity timeline (paged, filterable)" },
    Route { method: "GET", path: "/api/browser", summary: "Browser activity" },
    Route { method: "GET", path: "/api/system-events", summary: "System/lifecycle events" },
    // Screenshots (spec §33) — decrypt on demand, audit each view
    Route { method: "GET", path: "/api/screenshots", summary: "Screenshot metadata list" },
    Route { method: "GET", path: "/api/screenshots/:id/image", summary: "On-demand decrypt + stream (audited)" },
    // Storage / audit / integrity
    Route { method: "GET", path: "/api/storage", summary: "Usage vs quota + retention state" },
    Route { method: "GET", path: "/api/audit", summary: "Audit log (append-only)" },
    Route { method: "POST", path: "/api/integrity/verify", summary: "Run chain verification (spec §22)" },
    // Configuration (authorized change → history + CONFIGURATION_CHANGED + audit)
    Route { method: "GET", path: "/api/config", summary: "Current agent config + policy" },
    Route { method: "PUT", path: "/api/config/system-name", summary: "Rename device (device_id unchanged, spec §10)" },
    Route { method: "PUT", path: "/api/config/policy", summary: "Update collection policy (validated)" },
];
