"""SAML IdP state, mapping queue, and flush.

Loads the existing IdP (or marks it for creation) on first use, accumulates
new mappings produced by row processing, and flushes them in a single
GraphQL call at the end of the run.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, TYPE_CHECKING

from .graphql_queries import CREATE_SAML_IDP, GET_SAML_IDP, UPDATE_SAML_IDP
from .models import PendingSAMLMapping, SamlFlags

if TYPE_CHECKING:
    from .roles import RolesCache


# Signature matches OrgSpaceService.execute_graphql: (query, variable_values, operation_name) → result
GraphQLExecutor = Callable[[Any, dict[str, Any], str], Any]


class SamlIdpService:
    """Owns SAML IdP state for the run and batches all writes into a single flush.

    Loads the existing IdP (or marks one for creation) on first use, accumulates
    new mappings produced by row processing, then on `flush()` issues either
    `createSAMLIdP` (no IdP existed) or `updateSAMLIdP` (full-replace) in one call.
    """

    def __init__(
        self,
        execute_graphql: GraphQLExecutor,
        logger: logging.Logger,
        dry_run: bool,
        saml_metadata_url: str | None,
        saml_metadata_xml: str | None,
        email_domains: list[str] | None,
        enforce_saml: bool | None,
        sync_user_roles: bool | None,
        sign_authn: bool | None,
    ) -> None:
        self._execute_graphql = execute_graphql
        self._logger = logger
        self._dry_run = dry_run

        # Create-time parameters (used only if no IdP exists yet)
        self._saml_metadata_url = saml_metadata_url
        self._saml_metadata_xml = saml_metadata_xml
        self._email_domains = email_domains or []

        # CLI flag overrides — when None, preserve whatever the IdP already had.
        self._enforce_saml_override = enforce_saml is True
        self._sync_user_roles_override = sync_user_roles is True
        self._sign_authn_override = sign_authn is True

        # Default flags used when creating a new IdP (no existing values to preserve).
        self._flags = SamlFlags(
            enforce_saml=bool(enforce_saml),
            sync_user_roles=True if sync_user_roles is None else sync_user_roles,
            sign_authn=bool(sign_authn),
            allow_login_with_defaults=False,
        )

        # Loaded-on-demand state
        self._idp_id: str | None = None
        self._needs_creation: bool = False  # True when no IdP found yet
        self._existing_mappings: list[dict[str, Any]] = []
        self._existing_email_domains: list[str] = []  # re-sent on updateSAMLIdP
        self._pending: list[PendingSAMLMapping] = []
        # Set when reconcile or preflight mutates an entry in _existing_mappings
        # so flush() knows it needs to issue updateSAMLIdP even when _pending
        # is empty (the mutated existing entries need to be persisted).
        self._existing_dirty: bool = False

        # Rows whose (attr, org_role, space, role) matched an existing IdP
        # mapping exactly (status=already_exists, NOT in _pending). Tracked
        # so the preflight can spot CSV-internal contradictions where one row
        # wants to keep an existing legacy entry while another row wants the
        # same space migrated to custom (or vice versa).
        #
        # Each entry: (row_number, space_id, space_role, space_rbac_role_id).
        # Exactly one of space_role / space_rbac_role_id is non-empty (matching
        # whichever map the existing entry lived in).
        self._exact_match_uses: list[tuple[int, str, str, str]] = []

    # ── Read-only views for the preflight ─────────────────────────────────────
    # Return tuples (not live lists) so callers can't accidentally mutate
    # internal state outside the service's invariants. Mutation goes through
    # queue_mapping/drop_pending/record_exact_match only.

    @property
    def existing_mappings(self) -> tuple[dict[str, Any], ...]:
        """Existing IdP role mappings (frozen view)."""
        return tuple(self._existing_mappings)

    @property
    def pending(self) -> tuple[PendingSAMLMapping, ...]:
        """Queued mappings (frozen view). Mutate via `queue_mapping` / `drop_pending`."""
        return tuple(self._pending)

    @property
    def exact_match_uses(self) -> tuple[tuple[int, str, str, str], ...]:
        """Rows that matched an existing IdP mapping exactly. See `record_exact_match`."""
        return tuple(self._exact_match_uses)

    # ── Public API used by the runner ─────────────────────────────────────────

    def ensure_loaded(self) -> None:
        """Check for an existing SAMLIdP and load its role mappings (once).

        If no IdP exists, sets needs_creation=True and returns without raising —
        creation is deferred to flush() so all pending mappings can be included
        in a single createSAMLIdP call (the API requires at least one mapping
        when allowLoginWithDefaults=False).
        """
        if self._idp_id is not None or self._needs_creation:
            return
        self._logger.debug("Loading SAML IdP…")
        result = self._execute_graphql(GET_SAML_IDP, {}, "getSAMLIdP")
        edges = result["account"]["samlIdPs"]["edges"]
        if not edges:
            self._validate_creation_params()
            self._needs_creation = True
            self._logger.info(
                "No SAMLIdP found — will create one with all collected mappings."
            )
            return
        idp = edges[0]["node"]
        self._idp_id = idp["id"]
        self._existing_mappings = idp.get("roleMappings") or []
        self._existing_email_domains = [
            d["domain"] for d in (idp.get("emailDomainsList") or [])
        ]
        self._flags = SamlFlags(
            enforce_saml=idp.get("enforceSaml") or False,
            sync_user_roles=idp.get("syncUserRoles") or False,
            sign_authn=idp.get("signAuthn") or False,
            allow_login_with_defaults=idp.get("allowLoginWithDefaults") or False,
        )
        if self._enforce_saml_override:
            self._flags.enforce_saml = True
        if self._sync_user_roles_override:
            self._flags.sync_user_roles = True
        if self._sign_authn_override:
            self._flags.sign_authn = True
        self._logger.debug(
            "Found SAMLIdP %s with %d existing role mapping(s)",
            self._idp_id,
            len(self._existing_mappings),
        )

    def mapping_exists(
        self,
        space_id: str,
        org_role: str,
        space_role: str,
        space_rbac_role_id: str,
        attr_name: str,
        attr_value: str,
    ) -> bool:
        """True if any existing or already-queued mapping covers this combo.

        Handles all three space-role shapes:
          - inherited (both space_role and space_rbac_role_id empty)
          - legacy builtin (space_role set)
          - custom RBAC (space_rbac_role_id set)

        When the IdP doesn't exist yet (needs_creation=True) there are no
        existing mappings, so only the within-run dedup check applies.
        """
        for mapping in self._existing_mappings:
            attrs = mapping.get("attributesMap") or []
            legacy_spaces = mapping.get("spaceRolesMap") or []
            rbac_spaces = mapping.get("spaceRbacRolesMap") or []
            existing_org_role = (mapping.get("orgRole") or {}).get("roleId", "")
            has_attr = any(
                len(p) >= 2 and p[0] == attr_name and p[1] == attr_value for p in attrs
            )
            if not has_attr or existing_org_role != org_role:
                continue
            # Inherited — attr + org role is the full identity
            if not space_role and not space_rbac_role_id:
                return True
            if space_rbac_role_id and any(
                len(p) >= 2 and p[0] == space_id and p[1] == space_rbac_role_id
                for p in rbac_spaces
            ):
                return True
            if space_role and any(
                len(p) >= 2 and p[0] == space_id and p[1] == space_role
                for p in legacy_spaces
            ):
                return True
        # Also deduplicate within the current run
        return any(
            p.attr_name == attr_name
            and p.attr_value == attr_value
            and p.org_role == org_role
            and (
                (not space_role and not space_rbac_role_id)
                or (
                    space_rbac_role_id
                    and p.space_id == space_id
                    and p.space_rbac_role_id == space_rbac_role_id
                )
                or (
                    space_role and p.space_id == space_id and p.space_role == space_role
                )
            )
            for p in self._pending
        )

    def queue_mapping(self, mapping: PendingSAMLMapping) -> None:
        """Queue a new mapping for the next flush."""
        self._pending.append(mapping)

    def record_exact_match(
        self,
        row_number: int,
        space_id: str,
        space_role: str,
        space_rbac_role_id: str,
    ) -> None:
        """Track an already_exists row so the preflight can detect CSV-internal
        contradictions about the role-type for this space."""
        if space_role or space_rbac_role_id:
            self._exact_match_uses.append(
                (row_number, space_id, space_role, space_rbac_role_id)
            )

    def drop_pending(self, row_numbers: set[int]) -> None:
        """Remove pending mappings whose row failed in the preflight."""
        self._pending = [p for p in self._pending if p.row_number not in row_numbers]

    def convert_legacy_to_custom(
        self, row_number: int, space_id: str, roles: "RolesCache"
    ) -> tuple[str, str] | None:
        """Swap a pending legacy mapping for `(row_number, space_id)` to use a custom role.

        Looks up — or creates on the account — the legacy-equivalent custom RBAC
        role via `RolesCache.ensure_legacy_equivalent_role`, then mutates the
        pending mapping in place so the eventual flush sends it under
        `spaceRbacRolesMap` rather than `spaceRolesMap`.

        Returns `(legacy_role_key, new_custom_role_name)` on success, or `None`
        if no matching pending legacy mapping exists (e.g. the row was an
        already_exists exact-match rather than a queued mapping).
        """
        for p in self._pending:
            if (
                p.row_number == row_number
                and p.space_id == space_id
                and p.space_role
                and not p.space_rbac_role_id
            ):
                legacy_key = p.space_role
                relay_id, custom_name = roles.ensure_legacy_equivalent_role(
                    legacy_key
                )
                p.space_rbac_role_id = relay_id
                p.space_role = ""
                return legacy_key, custom_name
        return None

    def promote_existing_legacy_for_space(
        self, space_id: str, roles: "RolesCache"
    ) -> list[tuple[str, str]]:
        """Promote every existing legacy entry for `space_id` to a custom RBAC role.

        Scans `_existing_mappings`; for each `[space_id, legacy_key]` pair found
        under `spaceRolesMap`, looks up (or creates) the legacy-equivalent custom
        role via `roles.ensure_legacy_equivalent_role`, removes the pair from
        `spaceRolesMap`, and appends `[space_id, relay_id]` to `spaceRbacRolesMap`
        on the same mapping. Other entries on the mapping (other spaces, attrs,
        orgRole) are preserved.

        Idempotent: a re-run finds no remaining `spaceRolesMap` pairs for the
        space and is a no-op. `RolesCache.ensure_legacy_equivalent_role` itself
        is cache-backed, so each unique legacy key triggers at most one POST.

        Returns a deduped list of `(legacy_key, custom_name)` for each unique
        conversion, so callers can log + annotate matched rows.
        """
        conversions: dict[str, str] = {}
        for mapping in self._existing_mappings:
            legacy_entries = mapping.get("spaceRolesMap") or []
            if not legacy_entries:
                continue
            kept: list[list[str]] = []
            for pair in legacy_entries:
                if len(pair) < 2 or pair[0] != space_id:
                    kept.append(pair)
                    continue
                legacy_key = pair[1]
                relay_id, custom_name = roles.ensure_legacy_equivalent_role(
                    legacy_key
                )
                conversions[legacy_key] = custom_name
                rbac_entries = mapping.get("spaceRbacRolesMap")
                if rbac_entries is None:
                    rbac_entries = []
                    mapping["spaceRbacRolesMap"] = rbac_entries
                rbac_entries.append([space_id, relay_id])
            mapping["spaceRolesMap"] = kept
        if conversions:
            self._existing_dirty = True
        return list(conversions.items())

    def reconcile_pending_into_existing(
        self,
        on_absorbed: Callable[[int, str, str, str, str], None],
    ) -> None:
        """Absorb pending mappings into matching existing IdP mappings.

        For each pending `p`, search `_existing_mappings` for an entry that
        shares the same single `attributesMap` pair and `orgRole.roleId` as
        `p`. When found, reconcile `p`'s space-role into the existing mapping:

          - **idempotent**: existing already has [p.space_id, same_role] in
            the same map (legacy or RBAC) → drop pending, no mutation.
          - **replaced**: existing has [p.space_id, other_role] in the same
            map or the opposite map → swap to p's role, drop pending. We also
            remove any stale entry for p.space_id from the opposite map so
            the space ends up with exactly one role-type.
          - **extended**: existing has no entry for p.space_id → append the
            pair to the appropriate map on the existing mapping, drop pending.
          - **inherited**: pending has no space role (inherit-from-org-role)
            and existing already covers (attr, val, org_role) → drop pending.

        `on_absorbed(row_number, kind, attr_name, attr_value, prior_role_label)`
        is called once per absorbed pending. `kind` is one of:
        `"idempotent" | "replaced" | "extended" | "inherited"`.
        `prior_role_label` is the human-readable role the existing entry used
        before replacement (relay role-id or legacy key) — empty for the
        other kinds.
        """
        kept: list[PendingSAMLMapping] = []
        for p in self._pending:
            existing = self._find_existing_for(p.attr_name, p.attr_value, p.org_role)
            if existing is None:
                kept.append(p)
                continue

            # Inherited pending — any existing match means the row is already
            # covered (attribute pair + org role is the full identity).
            if not p.space_role and not p.space_rbac_role_id:
                on_absorbed(p.row_number, "inherited", p.attr_name, p.attr_value, "")
                continue

            legacy_entries = existing.setdefault("spaceRolesMap", []) or []
            rbac_entries = existing.setdefault("spaceRbacRolesMap", []) or []
            existing["spaceRolesMap"] = legacy_entries
            existing["spaceRbacRolesMap"] = rbac_entries

            # Locate any prior pair for the space, in either map. There should
            # be at most one after the preflight, but defensively handle both.
            prior_legacy_idx = next(
                (
                    i for i, pair in enumerate(legacy_entries)
                    if len(pair) >= 2 and pair[0] == p.space_id
                ),
                None,
            )
            prior_rbac_idx = next(
                (
                    i for i, pair in enumerate(rbac_entries)
                    if len(pair) >= 2 and pair[0] == p.space_id
                ),
                None,
            )

            target_map, target_pair = (
                ("rbac", [p.space_id, p.space_rbac_role_id])
                if p.space_rbac_role_id
                else ("legacy", [p.space_id, p.space_role])
            )

            if prior_legacy_idx is None and prior_rbac_idx is None:
                # Case 4: extended — append to the appropriate map.
                if target_map == "rbac":
                    rbac_entries.append(target_pair)
                else:
                    legacy_entries.append(target_pair)
                self._existing_dirty = True
                on_absorbed(
                    p.row_number, "extended", p.attr_name, p.attr_value, ""
                )
                continue

            # Determine the prior role label for messaging + idempotency check.
            prior_label = ""
            same_role = False
            if target_map == "rbac" and prior_rbac_idx is not None:
                prior_label = rbac_entries[prior_rbac_idx][1]
                same_role = prior_label == p.space_rbac_role_id
            elif target_map == "legacy" and prior_legacy_idx is not None:
                prior_label = legacy_entries[prior_legacy_idx][1]
                same_role = prior_label == p.space_role
            else:
                # Opposite-map collision (e.g. pending custom, existing legacy)
                # — never idempotent; treat as replace and capture the label.
                if prior_rbac_idx is not None:
                    prior_label = rbac_entries[prior_rbac_idx][1]
                elif prior_legacy_idx is not None:
                    prior_label = legacy_entries[prior_legacy_idx][1]

            if same_role:
                on_absorbed(
                    p.row_number, "idempotent", p.attr_name, p.attr_value, ""
                )
                continue

            # Case 3: replaced. Drop any prior entries in either map, then
            # insert the new pair in the target map.
            if prior_rbac_idx is not None:
                rbac_entries.pop(prior_rbac_idx)
            if prior_legacy_idx is not None:
                legacy_entries.pop(prior_legacy_idx)
            if target_map == "rbac":
                rbac_entries.append(target_pair)
            else:
                legacy_entries.append(target_pair)
            self._existing_dirty = True
            on_absorbed(
                p.row_number, "replaced", p.attr_name, p.attr_value, prior_label
            )

        self._pending = kept

    def collapse_pending_by_attributes(
        self,
        on_merged: Callable[[int, int, str, str], None],
    ) -> None:
        """Collapse remaining `_pending` entries sharing `(attr, val, org_role)`.

        The first entry in each group keeps its row as the owner; subsequent
        entries' `(space_id, role)` pairs are folded into the owner's
        `extra_space_*_pairs` and the entry is dropped from `_pending`.

        `on_merged(row_number, owner_row_number, attr_name, attr_value)` is
        called once per folded row.
        """
        owners: dict[tuple[str, str, str], PendingSAMLMapping] = {}
        kept: list[PendingSAMLMapping] = []
        for p in self._pending:
            key = (p.attr_name, p.attr_value, p.org_role)
            owner = owners.get(key)
            if owner is None:
                owners[key] = p
                kept.append(p)
                continue
            # Fold p's space pair onto the owner.
            if p.space_rbac_role_id:
                owner.extra_space_rbac_pairs.append(
                    (p.space_id, p.space_rbac_role_id)
                )
            elif p.space_role:
                owner.extra_space_legacy_pairs.append((p.space_id, p.space_role))
            # Inherited pendings (no role fields) are duplicates of the owner's
            # attribute-pair identity — fold them silently with no extra pair.
            on_merged(p.row_number, owner.row_number, p.attr_name, p.attr_value)
        self._pending = kept

    def _find_existing_for(
        self, attr_name: str, attr_value: str, org_role: str
    ) -> dict[str, Any] | None:
        """Return the first existing mapping whose single attributesMap pair
        and orgRole match `(attr_name, attr_value, org_role)`, else None."""
        for mapping in self._existing_mappings:
            attrs = mapping.get("attributesMap") or []
            existing_org_role = (mapping.get("orgRole") or {}).get("roleId", "")
            if existing_org_role != org_role:
                continue
            if any(
                len(p) >= 2 and p[0] == attr_name and p[1] == attr_value
                for p in attrs
            ):
                return mapping
        return None

    def has_pending(self) -> bool:
        """True if any mappings are queued for the next flush."""
        return bool(self._pending)

    def needs_flush(self) -> bool:
        """True if the next flush would persist any change — either new pending
        mappings or in-place mutations to existing mappings (from reconcile or
        the preflight's promote step)."""
        return bool(self._pending) or self._existing_dirty

    def pending_count(self) -> int:
        """Number of mappings currently queued for the next flush."""
        return len(self._pending)

    def pending_row_numbers(self) -> set[int]:
        """CSV row numbers behind the currently queued mappings."""
        return {p.row_number for p in self._pending}

    def flush(self) -> None:
        """Persist all pending mappings + any existing-mapping mutations in one call.

        - If the IdP already existed: updateSAMLIdP (full-replace, existing + new).
        - If no IdP existed yet: createSAMLIdP with all mappings included
          (the API requires at least one mapping when allowLoginWithDefaults=False).

        Leaves `_pending` intact on success so the caller can read
        `pending_count()` / `pending_row_numbers()` after the call. Should not
        be invoked when `dry_run` is true — the runner skips this entire path
        in dry-run mode.
        """
        if not self.needs_flush():
            return

        new_mappings = self._build_new_mappings_input()

        if self._needs_creation:
            self._create_idp_with_mappings(new_mappings)
            return

        if self._idp_id is None:
            return

        self._update_idp_with_mappings(new_mappings)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _validate_creation_params(self) -> None:
        """Raise early if the params needed to create a new IdP are missing."""
        if not self._email_domains:
            raise RuntimeError(
                "No SAML IdP found for this account. "
                "Provide --email-domains and either --saml-metadata-url or "
                "--saml-metadata-xml to create one automatically, or configure "
                "SAML in the Arize UI first."
            )
        if not self._saml_metadata_url and not self._saml_metadata_xml:
            raise RuntimeError(
                "No SAML IdP found and no metadata supplied. "
                "Provide --saml-metadata-url or --saml-metadata-xml to create one."
            )

    def _build_new_mappings_input(self) -> list[dict[str, Any]]:
        """Serialize `_pending` to the GraphQL `mappingsList` input shape.

        `extra_space_*_pairs` (populated by `collapse_pending_by_attributes`)
        are emitted on the same entry as the owner's primary pair, so multiple
        CSV rows that shared an `(attr, val, org_role)` end up in one mapping.
        """
        entries: list[dict[str, Any]] = []
        for p in self._pending:
            entry: dict[str, Any] = {
                "attributesMap": [[p.attr_name, p.attr_value]],
                "orgRole": {"orgId": p.org_id, "roleId": p.org_role},
                "isAccountAdmin": False,
            }
            rbac_pairs: list[list[str]] = []
            legacy_pairs: list[list[str]] = []
            if p.space_rbac_role_id:
                rbac_pairs.append([p.space_id, p.space_rbac_role_id])
            elif p.space_role:
                legacy_pairs.append([p.space_id, p.space_role])
            for space_id, role_id in p.extra_space_rbac_pairs:
                rbac_pairs.append([space_id, role_id])
            for space_id, role_key in p.extra_space_legacy_pairs:
                legacy_pairs.append([space_id, role_key])
            # Only emit a key when there's something to send; the backend
            # treats omission as "inherit from org role".
            if rbac_pairs:
                entry["spaceRbacRolesMap"] = rbac_pairs
            if legacy_pairs:
                entry["spaceRolesMap"] = legacy_pairs
            entries.append(entry)
        return entries

    def _create_idp_with_mappings(self, mappings_input: list[dict[str, Any]]) -> None:
        """Create a new SAMLIdP and include all pending mappings in one call."""
        self._logger.info(
            "Creating SAMLIdP (domains: %s) with %d mapping(s)…",
            ", ".join(self._email_domains),
            len(mappings_input),
        )
        idp_input: dict[str, Any] = {
            "emailDomainsList": [{"domain": d} for d in self._email_domains],
            "enforceSaml": self._flags.enforce_saml,
            "syncUserRoles": self._flags.sync_user_roles,
            "signAuthn": self._flags.sign_authn,
            "allowLoginWithDefaults": self._flags.allow_login_with_defaults,
            "roleMappings": {"mappingsList": mappings_input},
        }
        if self._saml_metadata_url:
            idp_input["metadataUrl"] = self._saml_metadata_url
        if self._saml_metadata_xml:
            idp_input["metadataXml"] = self._saml_metadata_xml

        result = self._execute_graphql(
            CREATE_SAML_IDP, {"input": idp_input}, "createSAMLIdP"
        )
        payload = result.get("createSAMLIdP", {})
        if payload.get("error"):
            raise RuntimeError(f"createSAMLIdP returned error: {payload['error']}")
        idp = payload["idp"]
        self._idp_id = idp["id"]
        self._existing_mappings = idp.get("roleMappings") or []
        self._logger.info("SAMLIdP created: %s", self._idp_id)

    def _update_idp_with_mappings(self, new_mappings: list[dict[str, Any]]) -> None:
        """Replace the IdP's mappings with `existing + new` via updateSAMLIdP.

        spaceRbacRolesMap must be passed through alongside spaceRolesMap; an
        updateSAMLIdP that omitted it would drop any existing custom-role
        mappings on the IdP.
        """
        mappings_input: list[dict[str, Any]] = []
        for m in self._existing_mappings:
            entry: dict[str, Any] = {
                "attributesMap": m.get("attributesMap") or [],
                "spaceRolesMap": m.get("spaceRolesMap") or [],
                "spaceRbacRolesMap": m.get("spaceRbacRolesMap") or [],
                "isAccountAdmin": m.get("isAccountAdmin") or False,
            }
            if m.get("id"):
                entry["id"] = m["id"]
            if m.get("orgRole"):
                entry["orgRole"] = {
                    "orgId": m["orgRole"]["orgId"],
                    "roleId": m["orgRole"]["roleId"],
                }
            mappings_input.append(entry)
        mappings_input.extend(new_mappings)

        self._logger.info(
            "Updating SAMLIdP: %d existing + %d new mapping(s)",
            len(self._existing_mappings),
            len(self._pending),
        )
        # Re-include the existing email domains — updateSAMLIdP requires at least one.
        email_domains_for_update = self._email_domains or self._existing_email_domains
        update_input: dict[str, Any] = {
            "id": self._idp_id,
            "roleMappings": {"mappingsList": mappings_input},
            "emailDomainsList": [{"domain": d} for d in email_domains_for_update],
            "enforceSaml": self._flags.enforce_saml,
            "syncUserRoles": self._flags.sync_user_roles,
            "signAuthn": self._flags.sign_authn,
            "allowLoginWithDefaults": self._flags.allow_login_with_defaults,
        }
        result = self._execute_graphql(
            UPDATE_SAML_IDP, {"input": update_input}, "updateSAMLIdP"
        )
        if result and result.get("updateSAMLIdP", {}).get("error"):
            raise RuntimeError(
                f"updateSAMLIdP returned error: {result['updateSAMLIdP']['error']}"
            )
