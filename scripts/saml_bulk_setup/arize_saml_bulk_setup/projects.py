"""Project resolution, restriction, user creation, and role-binding for --project-assign."""

from __future__ import annotations

import logging
from typing import Any

import requests
from arize.client import ArizeClient

from .config import ARIZE_REST_API_URL, PROJECT_INVITE_MODE
from .retry import with_retry


class ProjectService:
    """Create/find projects, restrict them, manage users, and assign project roles.

    All operations use the REST API (projects, resource-restrictions, users,
    role_bindings).
    """

    def __init__(
        self,
        api_key: str,
        logger: logging.Logger,
        dry_run: bool,
        arize_rest_url: str = ARIZE_REST_API_URL,
    ) -> None:
        self._logger = logger
        self._dry_run = dry_run
        self._arize_client = ArizeClient(api_key=api_key)

        self._rest_url = arize_rest_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        # (space_id, project_name) → project_id
        self._project_cache: dict[tuple[str, str], str] = {}
        self._projects_loaded_for: set[str] = set()

        # email_lower → user_id (loaded once on first use)
        self._user_cache: dict[str, str] = {}
        self._users_loaded = False

        # project_id → restricted (to avoid re-calling restrictResource)
        self._restricted: set[str] = set()

        # (user_id, project_id) pairs loaded from GET /v2/role-bindings in dry-run
        # so we only log "Would assign" for genuinely new bindings.
        self._existing_bindings: set[tuple[str, str]] = set()
        self._bindings_loaded = False

    # ── Public API ────────────────────────────────────────────────────────────

    def resolve_project(
        self, space_id: str, space_name: str, project_name: str
    ) -> tuple[str, str]:
        """Return (project_id, status). Creates the project if it doesn't exist."""
        self._load_projects_for_space(space_id, space_name)

        cache_key = (space_id, project_name)
        if cache_key in self._project_cache:
            return self._project_cache[cache_key], "already_exists"

        if self._dry_run:
            self._project_cache[cache_key] = project_name
            self._logger.info("[DRY RUN] Would create project: %s", project_name)
            return project_name, "dry_run"

        self._logger.info(
            "Creating project '%s' in space '%s'…", project_name, space_name
        )
        try:
            project = self._post(
                "/v2/projects",
                {"name": project_name, "space_id": space_id},
            )
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Failed to create project '{project_name}' in space '{space_name}': {exc}"
            ) from exc
        project_id = str(project.get("id", ""))
        if not project_id:
            raise RuntimeError(
                f"POST /v2/projects for '{project_name}' returned no id: {project}"
            )
        self._project_cache[cache_key] = project_id
        return project_id, "created"

    def restrict_project(self, project_id: str, label: str) -> str:
        """Make the project private via ArizeClient.resource_restrictions.restrict().

        Returns "restricted", "already_restricted", or "dry_run". Idempotent.
        """
        if project_id in self._restricted:
            return "already_restricted"

        if self._dry_run:
            self._logger.info("[DRY RUN] Would restrict project: %s", label)
            return "dry_run"

        try:
            self._arize_client.resource_restrictions.restrict(resource_id=project_id)
        except Exception as exc:
            msg_lower = str(exc).lower()
            if "already" in msg_lower or "conflict" in msg_lower or "409" in msg_lower:
                self._restricted.add(project_id)
                return "already_restricted"
            raise

        self._restricted.add(project_id)
        self._logger.debug("Project restricted: %s", label)
        return "restricted"

    def resolve_user(self, email: str, org_role: str) -> tuple[str, str]:
        """Return (user_id, status) for `email`, auto-creating the user if absent.

        `status` is "already_exists", "created", or "dry_run".

        New users are created with invite_mode=none (SSO-only, no email invite)
        and the org role from `arize_org_role` on the CSV row. This is required
        because role bindings need an existing user_id — SAML auto-creates users
        on first login, but we must pre-register them to bind project roles now.
        """
        self._ensure_users_loaded()

        key = email.lower()
        if key in self._user_cache:
            return self._user_cache[key], "already_exists"

        if self._dry_run:
            self._user_cache[key] = email
            self._logger.info("[DRY RUN] Would create user: %s", email)
            return email, "dry_run"

        self._logger.info("Creating user '%s'…", email)
        try:
            user = self._post(
                "/v2/users",
                {
                    "name": email.split("@", 1)[0],
                    "email": email,
                    # POST /v2/users role is a discriminated union:
                    # {"type": "predefined", "name": "admin"|"member"|"annotator"}.
                    # "viewer" has no direct equivalent, so fall back to "member".
                    "role": {
                        "type": "predefined",
                        "name": org_role
                        if org_role in ("admin", "member", "annotator")
                        else "member",
                    },
                    "invite_mode": PROJECT_INVITE_MODE,
                },
            )
        except requests.HTTPError as exc:
            if getattr(exc.response, "status_code", None) == 409:
                # Race condition: created between our list and this POST. Reload.
                self._users_loaded = False
                self._user_cache.clear()
                self._ensure_users_loaded()
                if key in self._user_cache:
                    return self._user_cache[key], "already_exists"
            raise RuntimeError(f"Failed to create user '{email}': {exc}") from exc
        user_id = str(user.get("id", ""))
        if not user_id:
            raise RuntimeError(f"POST /v2/users for '{email}' returned no id: {user}")
        self._user_cache[key] = user_id
        return user_id, "created"

    def assign_user_to_project(
        self, user_id: str, project_id: str, role_id: str, project_name: str = ""
    ) -> str:
        """Bind `user_id` to `project_id` with `role_id`.

        Returns "granted", "already_granted", or "dry_run". Idempotent.
        """
        if self._dry_run:
            self._ensure_bindings_loaded()
            if (user_id, project_id) in self._existing_bindings:
                return "already_granted"
            self._logger.info(
                "[DRY RUN] Would assign user %s to project '%s'",
                user_id,
                project_name or project_id,
            )
            return "dry_run"

        try:
            self._post(
                "/v2/role-bindings",
                {
                    "user_id": user_id,
                    "role_id": role_id,
                    "resource_type": "PROJECT",
                    "resource_id": project_id,
                },
            )
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status == 409:
                return "already_granted"
            raise RuntimeError(
                f"Failed to assign user {user_id} to project {project_id}: {exc}"
            ) from exc
        except requests.RequestException as exc:
            msg_lower = str(exc).lower()
            if (
                "already" in msg_lower
                or "duplicate" in msg_lower
                or "conflict" in msg_lower
            ):
                return "already_granted"
            raise

        return "granted"

    # ── Internals ─────────────────────────────────────────────────────────────

    def _load_projects_for_space(self, space_id: str, space_name: str) -> None:
        """Populate the (space_id, project_name) → project_id cache. Idempotent."""
        if space_id in self._projects_loaded_for:
            return
        if space_id.startswith("__dry_run_"):
            self._projects_loaded_for.add(space_id)
            return

        self._logger.debug("Loading projects for space '%s'…", space_name)
        for project in self._get_paginated(
            "/v2/projects", "projects", {"space_id": space_id}
        ):
            name = project.get("name") or ""
            pid = project.get("id") or ""
            if not name or not pid:
                continue
            self._project_cache[(space_id, name)] = str(pid)
            self._logger.debug("  project: %s (%s)", name, pid)
        self._projects_loaded_for.add(space_id)

    def _ensure_users_loaded(self) -> None:
        """Populate email → user_id cache via paginated GET /v2/users. Idempotent."""
        if self._users_loaded:
            return
        self._logger.debug("Loading account users for project assignment…")
        for user in self._get_paginated("/v2/users", "users", {}):
            email = (user.get("email") or "").lower()
            uid = user.get("id") or ""
            if email and uid:
                self._user_cache[email] = str(uid)
        self._users_loaded = True
        self._logger.debug("  loaded %d user(s)", len(self._user_cache))

    def _ensure_bindings_loaded(self) -> None:
        """Populate existing project role-bindings cache. Used in dry-run only."""
        if self._bindings_loaded:
            return
        self._logger.debug("Loading existing project role bindings…")
        for binding in self._get_paginated(
            "/v2/role-bindings", "role_bindings", {"resource_type": "PROJECT"}
        ):
            uid = binding.get("user_id") or ""
            rid = binding.get("resource_id") or ""
            if uid and rid:
                self._existing_bindings.add((str(uid), str(rid)))
        self._bindings_loaded = True
        self._logger.debug(
            "  loaded %d project binding(s)", len(self._existing_bindings)
        )

    def _get_paginated(
        self, path: str, items_key: str, params: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Collect all items from a paginated REST endpoint."""
        url = f"{self._rest_url}{path}"
        cursor: str | None = None
        items: list[dict[str, Any]] = []
        while True:
            page_params: dict[str, Any] = {"limit": 100, **params}
            if cursor:
                page_params["cursor"] = cursor

            def fetch_page() -> requests.Response:
                r = requests.get(
                    url, headers=self._headers, params=page_params, timeout=30
                )
                r.raise_for_status()
                return r

            resp = with_retry(fetch_page, f"GET {path}", self._logger)
            payload = resp.json()
            for item in payload.get(items_key) or []:
                items.append(item)
            pagination = payload.get("pagination") or {}
            if not pagination.get("has_more"):
                break
            cursor = pagination.get("next_cursor")
            if not cursor:
                break
        return items

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """POST JSON to `path`, raise on non-2xx, return parsed response."""
        url = f"{self._rest_url}{path}"

        def post() -> requests.Response:
            r = requests.post(url, headers=self._headers, json=body, timeout=30)
            if not r.ok:
                raise requests.HTTPError(
                    f"POST {path} → {r.status_code}: {r.text}", response=r
                )
            return r

        resp = with_retry(post, f"POST {path}", self._logger)
        return resp.json() if resp.content else {}
