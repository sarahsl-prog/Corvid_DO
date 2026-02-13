"""Pydantic models for Analysis API requests and responses."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from corvid.api.models.ioc import IOCCreate, IOCType


class AnalysisResponse(BaseModel):
    """Response model for a threat analysis result (from database)."""

    id: UUID
    ioc_ids: list[str]
    analysis_text: str
    confidence: float
    mitre_techniques: list[str]
    recommended_actions: list[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class AnalyzeRequest(BaseModel):
    """Request model for submitting IOCs for AI-powered analysis."""

    iocs: list[IOCCreate] = Field(..., min_length=1, max_length=10)
    context: str = Field(
        default="",
        max_length=2000,
        description="Optional context about where/how the IOC was observed",
    )
    priority: str = Field(
        default="medium",
        pattern="^(low|medium|high)$",
        description="Analysis priority level",
    )


class AnalysisResultItem(BaseModel):
    """A single IOC analysis result from the Gradient agent."""

    ioc: IOCCreate
    severity: float = Field(..., ge=0.0, le=10.0, description="Severity score 0-10")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in the assessment 0-1")
    summary: str = Field(..., description="Brief summary of findings")
    related_cves: list[str] = Field(default_factory=list, description="Related CVE IDs")
    mitre_techniques: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs"
    )
    enrichments: dict[str, Any] = Field(
        default_factory=dict, description="Enrichment data by source"
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Recommended remediation actions"
    )


class AnalyzeResponse(BaseModel):
    """Response model for the /analyze endpoint."""

    analysis_id: UUID
    status: str = Field(
        ...,
        pattern="^(completed|partial|failed)$",
        description="Overall analysis status",
    )
    results: list[AnalysisResultItem] = Field(
        default_factory=list, description="Analysis results per IOC"
    )


class AgentAnalysisOutput(BaseModel):
    """Schema for the structured output expected from the Gradient agent.

    The agent must return JSON matching this schema.
    """

    summary: str = Field(..., description="2-3 sentence summary of findings")
    severity: float = Field(..., ge=0.0, le=10.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    related_cves: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    enrichment_findings: dict[str, str] = Field(
        default_factory=dict, description="Key findings from each source consulted"
    )
    recommended_actions: list[str] = Field(default_factory=list)
    related_iocs: list[str] = Field(
        default_factory=list, description="Any associated indicators discovered"
    )
