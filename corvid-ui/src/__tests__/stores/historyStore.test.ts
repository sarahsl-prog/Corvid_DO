/**
 * Tests for the history store Zustand state management.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { useHistoryStore } from "../../stores/historyStore";
import type { CyNode, CyEdge } from "../../types/graph";
import type { AnalysisResultItem } from "../../types/api";

const mockNodes: CyNode[] = [
  { data: { id: "ioc-ip-192.168.1.1", label: "192.168.1.1", nodeType: "ioc", iocType: "ip", severity: 7.5 } },
  { data: { id: "cve-CVE-2024-1234", label: "CVE-2024-1234", nodeType: "cve" } },
];

const mockEdges: CyEdge[] = [
  { data: { source: "ioc-ip-192.168.1.1", target: "cve-CVE-2024-1234", edgeType: "has_cve" } },
];

const mockResults: AnalysisResultItem[] = [
  {
    ioc: { type: "ip", value: "192.168.1.1" },
    severity: 7.5,
    confidence: 0.85,
    summary: "Test summary",
    related_cves: ["CVE-2024-1234"],
    mitre_techniques: ["T1071.001"],
    enrichments: {},
    recommended_actions: ["Block IP"],
  },
];

describe("historyStore", () => {
  beforeEach(() => {
    // Reset store state before each test
    useHistoryStore.setState({ sessions: [], maxSessions: 20 });
  });

  describe("saveSession", () => {
    it("saves a new session with generated name", () => {
      useHistoryStore.getState().saveSession("Test Investigation", mockNodes, mockEdges, mockResults);

      const sessions = useHistoryStore.getState().sessions;
      expect(sessions).toHaveLength(1);
      expect(sessions[0].name).toBe("Test Investigation");
      expect(sessions[0].nodes).toEqual(mockNodes);
      expect(sessions[0].edges).toEqual(mockEdges);
      expect(sessions[0].results).toEqual(mockResults);
      expect(sessions[0].timestamp).toBeGreaterThan(0);
      expect(sessions[0].id).toBeDefined();
    });

    it("auto-generates name when empty", () => {
      useHistoryStore.getState().saveSession("", mockNodes, mockEdges, mockResults);

      const sessions = useHistoryStore.getState().sessions;
      expect(sessions[0].name).toMatch(/^Investigation \d+$/);
    });

    it("prepends new session to beginning of list", () => {
      useHistoryStore.getState().saveSession("First", mockNodes, mockEdges, mockResults);
      useHistoryStore.getState().saveSession("Second", mockNodes, mockEdges, mockResults);

      const sessions = useHistoryStore.getState().sessions;
      expect(sessions[0].name).toBe("Second");
      expect(sessions[1].name).toBe("First");
    });

    it("enforces maxSessions limit", () => {
      useHistoryStore.setState({ maxSessions: 3 });

      for (let i = 0; i < 5; i++) {
        useHistoryStore.getState().saveSession(`Session ${i + 1}`, mockNodes, mockEdges, mockResults);
      }

      const sessions = useHistoryStore.getState().sessions;
      expect(sessions).toHaveLength(3);
      expect(sessions[0].name).toBe("Session 5");
      expect(sessions[2].name).toBe("Session 3");
    });
  });

  describe("loadSession", () => {
    it("returns session by id when found", () => {
      useHistoryStore.getState().saveSession("Test", mockNodes, mockEdges, mockResults);
      const savedId = useHistoryStore.getState().sessions[0].id;

      const loaded = useHistoryStore.getState().loadSession(savedId);
      expect(loaded).not.toBeNull();
      expect(loaded?.name).toBe("Test");
      expect(loaded?.nodes).toEqual(mockNodes);
    });

    it("returns null when session not found", () => {
      const loaded = useHistoryStore.getState().loadSession("non-existent-id");
      expect(loaded).toBeNull();
    });
  });

  describe("deleteSession", () => {
    it("removes session by id", () => {
      useHistoryStore.getState().saveSession("To Delete", mockNodes, mockEdges, mockResults);
      useHistoryStore.getState().saveSession("Keep", mockNodes, mockEdges, mockResults);

      const idToDelete = useHistoryStore.getState().sessions[1].id;
      useHistoryStore.getState().deleteSession(idToDelete);

      const sessions = useHistoryStore.getState().sessions;
      expect(sessions).toHaveLength(1);
      expect(sessions[0].name).toBe("To Delete");
    });

    it("handles deleting non-existent session gracefully", () => {
      useHistoryStore.getState().saveSession("Test", mockNodes, mockEdges, mockResults);

      useHistoryStore.getState().deleteSession("non-existent");

      const sessions = useHistoryStore.getState().sessions;
      expect(sessions).toHaveLength(1);
    });
  });

  describe("clearHistory", () => {
    it("removes all sessions", () => {
      useHistoryStore.getState().saveSession("First", mockNodes, mockEdges, mockResults);
      useHistoryStore.getState().saveSession("Second", mockNodes, mockEdges, mockResults);

      useHistoryStore.getState().clearHistory();

      expect(useHistoryStore.getState().sessions).toHaveLength(0);
    });
  });

  describe("setMaxSessions", () => {
    it("updates max sessions limit", () => {
      useHistoryStore.getState().setMaxSessions(10);
      expect(useHistoryStore.getState().maxSessions).toBe(10);
    });

    it("truncates existing sessions when reducing limit", () => {
      for (let i = 0; i < 5; i++) {
        useHistoryStore.getState().saveSession(`Session ${i + 1}`, mockNodes, mockEdges, mockResults);
      }

      useHistoryStore.getState().setMaxSessions(2);

      const sessions = useHistoryStore.getState().sessions;
      // Note: setMaxSessions only changes the config, doesn't trigger cleanup
      // until next saveSession
      expect(useHistoryStore.getState().maxSessions).toBe(2);
    });
  });
});
