"use client";

import {
  Component,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { Html, OrbitControls } from "@react-three/drei";
import { Canvas, useThree } from "@react-three/fiber";
import { createRelationshipLineGeometry, toScenePosition } from "./graph-geometry";
import type {
  IntelligenceNode,
  IntelligenceRelationship,
  PositionedIntelligenceNode,
  Locale,
} from "./types";
import { getMessages } from "./translations";
import { safeDisplayText } from "./display-text";
import type { GraphViewSlice } from "./graph-view";
import { subscribeToWebGLContextLoss } from "./webgl-context";
import styles from "./Theater3DCanvas.module.css";

type Theater3DCanvasProps = {
  graphView: GraphViewSlice;
  selectedNodeId: string;
  locale: Locale;
  onSelectNode: (nodeId: string) => void;
  onFallback: (reason?: "context-lost") => void;
};

const entityColors: Record<IntelligenceNode["type"], string> = {
  "threat-actor": "#c4a6ff",
  campaign: "#76a9ff",
  domain: "#59e1d2",
  incident: "#ffbc72",
  asset: "#9be3a7",
};

function WebGLContextLossGuard({ onContextLost }: { onContextLost: () => void }) {
  const { gl } = useThree();
  useEffect(
    () => subscribeToWebGLContextLoss(gl.domElement, onContextLost),
    [gl, onContextLost],
  );
  return null;
}

function RelationshipScene({
  nodes,
  relationships,
  selectedNodeId,
  onSelectNode,
}: {
  nodes: PositionedIntelligenceNode[];
  relationships: IntelligenceRelationship[];
  selectedNodeId: string;
  onSelectNode: (nodeId: string) => void;
}) {
  const positions = useMemo(
    () => new Map(nodes.map((node) => [node.id, toScenePosition(node)])),
    [nodes],
  );
  const selectedRelationships = useMemo(
    () =>
      relationships.filter(
        (relationship) =>
          relationship.sourceId === selectedNodeId ||
          relationship.targetId === selectedNodeId,
      ),
    [relationships, selectedNodeId],
  );
  const allEdgeGeometry = useMemo(
    () => createRelationshipLineGeometry(nodes, relationships),
    [nodes, relationships],
  );
  const selectedEdgeGeometry = useMemo(
    () => createRelationshipLineGeometry(nodes, selectedRelationships),
    [nodes, selectedRelationships],
  );

  useEffect(() => () => allEdgeGeometry.dispose(), [allEdgeGeometry]);
  useEffect(() => () => selectedEdgeGeometry.dispose(), [selectedEdgeGeometry]);

  return (
    <>
      <color attach="background" args={["#06111c"]} />
      <ambientLight intensity={1.25} />
      <pointLight position={[0, 4, 7]} intensity={24} color="#7ddde2" />
      <pointLight position={[-5, -3, 2]} intensity={9} color="#648fff" />

      {relationships.length > 0 && (
        <lineSegments geometry={allEdgeGeometry}>
          <lineBasicMaterial color="#3f8296" transparent opacity={0.58} />
        </lineSegments>
      )}
      {selectedRelationships.length > 0 && (
        <lineSegments geometry={selectedEdgeGeometry}>
          <lineBasicMaterial color="#6fe2d9" transparent opacity={0.98} />
        </lineSegments>
      )}

      {nodes.map((node) => {
        const position = positions.get(node.id);
        if (!position) return null;
        const selected = selectedNodeId === node.id;
        const color = entityColors[node.type];

        return (
          <group key={node.id} position={position}>
            <mesh
              scale={selected ? 1.16 : 1}
              onClick={(event) => {
                event.stopPropagation();
                onSelectNode(node.id);
              }}
            >
              <icosahedronGeometry args={[0.34, 1]} />
              <meshStandardMaterial
                color={color}
                emissive={color}
                emissiveIntensity={selected ? 0.6 : 0.2}
                roughness={0.32}
                metalness={0.12}
              />
            </mesh>
            <mesh scale={selected ? 1.42 : 1.2}>
              <ringGeometry args={[0.42, 0.45, 32]} />
              <meshBasicMaterial
                color={selected ? "#f1c777" : color}
                transparent
                opacity={selected ? 0.9 : 0.44}
                side={2}
              />
            </mesh>
            <Html position={[0, -0.68, 0]} center distanceFactor={9}>
              <bdi className={styles.nodeLabel} dir="auto">{safeDisplayText(node.label)}</bdi>
            </Html>
          </group>
        );
      })}

      <OrbitControls
        makeDefault
        enableDamping={false}
        enablePan={false}
        minDistance={7}
        maxDistance={18}
        rotateSpeed={0.55}
      />
    </>
  );
}

type ErrorBoundaryProps = {
  children: ReactNode;
  fallback: ReactNode;
  onError: () => void;
};

type ErrorBoundaryState = {
  hasError: boolean;
};

type CanvasFailure = "initialization" | "context-lost";

function CanvasUnavailable({ onUnavailable }: { onUnavailable: () => void }) {
  useEffect(() => {
    onUnavailable();
  }, [onUnavailable]);
  return null;
}

class SceneErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch() {
    this.props.onError();
  }

  render() {
    return this.state.hasError ? this.props.fallback : this.props.children;
  }
}

export function Theater3DCanvas({
  graphView,
  selectedNodeId,
  locale,
  onSelectNode,
  onFallback,
}: Theater3DCanvasProps) {
  const messages = getMessages(locale);
  const [canvasFailure, setCanvasFailure] = useState<CanvasFailure | null>(null);
  const reportCanvasFailure = useCallback((failure: CanvasFailure) => {
    setCanvasFailure(failure);
    onFallback(failure === "context-lost" ? "context-lost" : undefined);
  }, [onFallback]);
  const reportCanvasUnavailable = useCallback(
    () => reportCanvasFailure("initialization"),
    [reportCanvasFailure],
  );
  const reportContextLost = useCallback(
    () => reportCanvasFailure("context-lost"),
    [reportCanvasFailure],
  );
  const fallback = (
    <div className={styles.fallback} role="alert">
      <p>{canvasFailure === "context-lost" ? messages.canvasLostFallback : messages.canvasFallback}</p>
      <button type="button" onClick={() => onFallback()}>
        {messages.switchTo2d}
      </button>
    </div>
  );

  if (canvasFailure) {
    return <div className={styles.canvasFrame}>{fallback}</div>;
  }

  return (
    <div className={styles.canvasFrame}>
      <SceneErrorBoundary fallback={fallback} onError={onFallback}>
        <div aria-hidden="true">
          <Canvas
            camera={{ position: [0, 0, 12], fov: 48 }}
            dpr={[1, 1.5]}
            frameloop="demand"
            gl={{ antialias: true, alpha: true, powerPreference: "low-power" }}
            fallback={<CanvasUnavailable onUnavailable={reportCanvasUnavailable} />}
          >
            <WebGLContextLossGuard onContextLost={reportContextLost} />
            <RelationshipScene
              nodes={graphView.nodes}
              relationships={graphView.relationships}
              selectedNodeId={selectedNodeId}
              onSelectNode={onSelectNode}
            />
          </Canvas>
        </div>
      </SceneErrorBoundary>
    </div>
  );
}
