"""GraphQL operations used directly by the script.

Only SAML IdP operations remain on GraphQL — the REST API spec exposes no
SAML endpoints. Org and space CRUD now go through REST in `orgs_spaces.py`.
These three operations are issued through the toolkit's authenticated
`_graphql_client` via `OrgSpaceService.execute_graphql`.
"""

from __future__ import annotations

from gql import gql

CREATE_SAML_IDP = gql("""
    mutation createSAMLIdP($input: CreateSAMLIdPInput!) {
        createSAMLIdP(input: $input) {
            idp {
                id
                roleMappings {
                    id
                    attributesMap
                    spaceRolesMap
                    spaceRbacRolesMap
                    isAccountAdmin
                    orgRole {
                        orgId
                        roleId
                    }
                }
            }
            error
        }
    }
""")

GET_SAML_IDP = gql("""
    query getSAMLIdP {
        account {
            samlIdPs(first: 1) {
                edges {
                    node {
                        id
                        emailDomainsList {
                            domain
                        }
                        enforceSaml
                        syncUserRoles
                        signAuthn
                        roleMappings {
                            id
                            attributesMap
                            spaceRolesMap
                            spaceRbacRolesMap
                            isAccountAdmin
                            orgRole {
                                orgId
                                roleId
                            }
                        }
                        allowLoginWithDefaults
                    }
                }
            }
        }
    }
""")

UPDATE_SAML_IDP = gql("""
    mutation updateSAMLIdP($input: UpdateSAMLIdPInput!) {
        updateSAMLIdP(input: $input) {
            idp {
                id
                roleMappings {
                    id
                    attributesMap
                    spaceRolesMap
                    spaceRbacRolesMap
                }
            }
            error
        }
    }
""")
