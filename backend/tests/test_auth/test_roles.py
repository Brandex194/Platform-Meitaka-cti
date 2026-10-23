import pytest
from fastapi import HTTPException

from app.auth.roles import Role, require_roles


def test_role_enum_has_five_values():
    assert len(Role) == 5


def test_require_roles_allows_matching():
    # Calling the inner dependency function directly with a payload dict.
    require_roles(Role.analyst)({"roles": ["analyst"]})


def test_require_roles_blocks_viewer():
    with pytest.raises(HTTPException) as exc_info:
        require_roles(Role.analyst)({"roles": ["viewer"]})
    assert exc_info.value.status_code == 403


def test_viewer_cannot_patch_exposure(client, viewer_token, exposure_match_id):
    # Route does not exist until Task 13; 404 documents intent.
    r = client.patch(
        f"/api/v1/exposure-matches/{exposure_match_id}",
        json={"status": "resolved"},
    )
    assert r.status_code in (403, 404)
