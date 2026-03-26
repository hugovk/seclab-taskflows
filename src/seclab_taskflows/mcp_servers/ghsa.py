# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import logging

from fastmcp import FastMCP
from pydantic import Field
import re
import json
from urllib.parse import urlparse, parse_qs
from .gh_code_scanning import call_api
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name
from .ghsa_models import GHSA, GHSASummary, Base
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from .utils import process_repo

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_ghsa.log"),
    filemode="a",
)

mcp = FastMCP("GitHubRepoAdvisories")

MEMORY = mcp_data_dir("seclab-taskflows", "ghsa", "GHSA_DIR")


def ghsa_to_dict(result):
    return {
        "id": result.id,
        "ghsa_id": result.ghsa_id,
        "repo": result.repo.lower(),
        "severity": result.severity,
        "cve_id": result.cve_id,
        "description": result.description,
        "summary": result.summary,
        "published_at": result.published_at,
        "state": result.state,
    }


def ghsa_summary_to_dict(summary):
    return {
        "id": summary.id,
        "repo": summary.repo.lower(),
        "total_advisories": summary.total_advisories,
        "high_severity_count": summary.high_severity_count,
        "medium_severity_count": summary.medium_severity_count,
        "low_severity_count": summary.low_severity_count,
        "summary_notes": summary.summary_notes,
    }

class GHSABackend:
    def __init__(self, db_dir: str):
        # Directory in which the GHSA SQLite database file will be stored.
        self.db_dir = db_dir
        if not Path(self.db_dir).exists():
            db_uri = "sqlite://"
        else:
            db_uri = f"sqlite:///{self.db_dir}/ghsa.db"
        self.engine = create_engine(db_uri, echo=False)
        Base.metadata.create_all(
            self.engine,
            tables=[
                GHSA.__table__,
                GHSASummary.__table__,
            ],
        )

    def store_new_ghsa(self, repo, ghsa_id, severity, cve_id, description, summary, published_at, state):
        with Session(self.engine) as session:
            existing = session.query(GHSA).filter_by(repo=repo, ghsa_id=ghsa_id).first()
            if existing:
                if severity:
                    existing.severity = severity
                if cve_id:
                    existing.cve_id = cve_id
                if description:
                    existing.description = description
                if summary:
                    existing.summary = summary
                if published_at:
                    existing.published_at = published_at
                if state:
                    existing.state = state
            else:
                new_ghsa = GHSA(
                    repo=repo,
                    ghsa_id=ghsa_id,
                    severity=severity,
                    cve_id=cve_id,
                    description=description,
                    summary=summary,
                    published_at=published_at,
                    state=state,
                )
                session.add(new_ghsa)
            session.commit()
        return f"Updated or added GHSA {ghsa_id} for {repo}"

    def get_ghsa(self, repo, ghsa_id):
        with Session(self.engine) as session:
            existing = session.query(GHSA).filter_by(repo=repo, ghsa_id=ghsa_id).first()
        if not existing:
            return None
        return ghsa_to_dict(existing)

    def get_ghsas(self, repo):
        with Session(self.engine) as session:
            existing = session.query(GHSA).filter_by(repo=repo).all()
        return [ghsa_to_dict(ghsa) for ghsa in existing]

    def store_new_ghsa_summary(
        self,
        repo,
        total_advisories,
        high_severity_count,
        medium_severity_count,
        low_severity_count,
        summary_notes,
    ):
        with Session(self.engine) as session:
            existing = session.query(GHSASummary).filter_by(repo=repo).first()
            if existing:
                existing.total_advisories = total_advisories
                existing.high_severity_count = high_severity_count
                existing.medium_severity_count = medium_severity_count
                existing.low_severity_count = low_severity_count
                existing.summary_notes = (existing.summary_notes or "") + (summary_notes or "")
            else:
                new_summary = GHSASummary(
                    repo=repo,
                    total_advisories=total_advisories,
                    high_severity_count=high_severity_count,
                    medium_severity_count=medium_severity_count,
                    low_severity_count=low_severity_count,
                    summary_notes=summary_notes,
                )
                session.add(new_summary)
            session.commit()
        return f"Updated or added GHSA summary for {repo}"

    def get_ghsa_summary(self, repo):
        with Session(self.engine) as session:
            existing = session.query(GHSASummary).filter_by(repo=repo).first()
        if not existing:
            return None
        return ghsa_summary_to_dict(existing)

    def clear_repo(self, repo):
        with Session(self.engine) as session:
            session.query(GHSA).filter_by(repo=repo).delete()
            session.query(GHSASummary).filter_by(repo=repo).delete()
            session.commit()
        return f"Cleared GHSA results for repo {repo}"


backend = GHSABackend(MEMORY)

# The advisories contain a lot of information, so we need to filter
# some of it out to avoid exceeding the maximum prompt size.
def parse_advisory(advisory: dict) -> dict:
    logging.debug(f"advisory: {advisory}")
    return {
        "ghsa_id": advisory.get("ghsa_id") or "",
        "cve_id": advisory.get("cve_id") or "",
        "summary": advisory.get("summary") or "",
        "description": advisory.get("description") or "",
        "severity": advisory.get("severity") or "",
        "published_at": advisory.get("published_at") or "",
        "state": advisory.get("state") or "",
    }


async def fetch_GHSA_list_from_gh(owner: str, repo: str) -> str | list:
    """Fetch all security advisories for a specific repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
    params = {"per_page": 100}
    # See https://github.com/octokit/plugin-paginate-rest.js/blob/8ec2713699ee473ee630be5c8a66b9665bcd4173/src/iterator.ts#L40
    link_pattern = re.compile(r'<([^<>]+)>;\s*rel="next"')
    results = []
    while True:
        resp = await call_api(url, params)
        if isinstance(resp, str):
            return resp
        resp_headers = resp.headers
        link = resp_headers.get("link", "")
        resp = resp.json()
        if isinstance(resp, list):
            results += [parse_advisory(advisory) for advisory in resp]
        else:
            return "Could not parse response"
        m = link_pattern.search(link)
        if not m:
            break
        url = m.group(1)
        params = parse_qs(urlparse(url).query)

    if results:
        return results
    return "No advisories found."


@mcp.tool()
async def fetch_GHSA_list(
    owner: str = Field(description="The owner of the repo"), repo: str = Field(description="The repository name")
) -> str:
    """Fetch all GitHub Security Advisories (GHSAs) for a specific repository."""
    results = await fetch_GHSA_list_from_gh(owner, repo)
    if isinstance(results, str):
        return results
    return json.dumps(results, indent=2)

@mcp.tool()
async def fetch_and_store_GHSA_list(
    owner: str = Field(description="The owner of the repo"), repo: str = Field(description="The repository name"),
    return_results: bool = Field(description="Whether to return the fetched results as a JSON string", default=False)
) -> str:
    """Fetch all GitHub Security Advisories (GHSAs) for a specific repository and store them in the database."""
    results = await fetch_GHSA_list_from_gh(owner, repo)
    if isinstance(results, str):
        return results
    for advisory in results:
        backend.store_new_ghsa(
            process_repo(owner, repo),
            advisory["ghsa_id"],
            advisory["severity"],
            advisory["cve_id"],
            advisory["description"],
            advisory["summary"],
            advisory["published_at"],
            advisory["state"],
        )
    if return_results:
        return json.dumps(results, indent=2)
    return f"Fetched and stored {len(results)} GHSAs for {owner}/{repo}"

@mcp.tool()
def store_new_ghsa(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    ghsa_id: str = Field(description="The GHSA ID of the advisory"),
    severity: str = Field(description="The severity of the advisory"),
    cve_id: str = Field(description="The CVE ID if available", default=""),
    description: str = Field(description="Description for this advisory", default=""),
    summary: str = Field(description="Summary for this advisory", default=""),
    published_at: str = Field(description="Published timestamp for this advisory", default=""),
    state: str = Field(description="State for this advisory (e.g. published, withdrawn)", default=""),
):
    """Store a GHSA advisory record in the database."""
    return backend.store_new_ghsa(
        process_repo(owner, repo), ghsa_id, severity, cve_id, description, summary, published_at, state
    )

@mcp.tool()
def get_ghsa_from_db(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    ghsa_id: str = Field(description="The GHSA ID of the advisory"),
):
    """Get a GHSA advisory record from the database."""
    repo_name = process_repo(owner, repo)
    result = backend.get_ghsa(repo_name, ghsa_id)
    if not result:
        return f"Error: No GHSA entry exists in repo: {repo_name} and ghsa_id {ghsa_id}"
    return json.dumps(result)


@mcp.tool()
def get_ghsas_for_repo_from_db(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Get all GHSA advisory records for a repository."""
    return json.dumps(backend.get_ghsas(process_repo(owner, repo)))

@mcp.tool()
def store_new_ghsa_summary(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    total_advisories: int = Field(description="Total number of advisories"),
    high_severity_count: int = Field(description="Number of high severity advisories"),
    medium_severity_count: int = Field(description="Number of medium severity advisories"),
    low_severity_count: int = Field(description="Number of low severity advisories"),
    summary_notes: str = Field(description="Notes for the advisory summary", default=""),
):
    """Store GHSA summary statistics for a repository."""
    return backend.store_new_ghsa_summary(
        process_repo(owner, repo),
        total_advisories,
        high_severity_count,
        medium_severity_count,
        low_severity_count,
        summary_notes,
    )


@mcp.tool()
def add_ghsa_summary_notes(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    summary_notes: str = Field(description="New notes for the advisory summary", default=""),
):
    """Append notes to the GHSA summary for a repository."""
    repo_name = process_repo(owner, repo)
    existing = backend.get_ghsa_summary(repo_name)
    if not existing:
        return f"Error: No GHSA summary exists in repo: {repo_name}"
    return backend.store_new_ghsa_summary(
        repo_name,
        existing["total_advisories"],
        existing["high_severity_count"],
        existing["medium_severity_count"],
        existing["low_severity_count"],
        summary_notes,
    )


@mcp.tool()
def get_ghsa_summary(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Get the GHSA summary for a repository."""
    repo_name = process_repo(owner, repo)
    result = backend.get_ghsa_summary(repo_name)
    if not result:
        return f"Error: No GHSA summary exists in repo: {repo_name}"
    return json.dumps(result)


@mcp.tool()
def clear_repo(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Clear GHSA and GHSA summary records for a repository."""
    return backend.clear_repo(process_repo(owner, repo))


async def fetch_GHSA_details_from_gh(owner: str, repo: str, ghsa_id: str) -> str | dict:
    """Fetch the details of a repository security advisory."""
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    resp = await call_api(url, {})
    if isinstance(resp, str):
        return resp
    if resp:
        return resp.json()
    return "Not found."


@mcp.tool()
async def fetch_GHSA_details(
    owner: str = Field(description="The owner of the repo"),
    repo: str = Field(description="The repository name"),
    ghsa_id: str = Field(description="The ghsa_id of the advisory"),
) -> str:
    """Fetch a GitHub Security Advisory for a specific repository and GHSA ID."""
    results = await fetch_GHSA_details_from_gh(owner, repo, ghsa_id)
    if isinstance(results, str):
        return results
    return json.dumps(results, indent=2)


if __name__ == "__main__":
    mcp.run(show_banner=False)
