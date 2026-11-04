"use client";

import {
  Component,
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { Html, Line, OrbitControls } from "@react-three/drei";
import { Canvas } from "@react-three/fiber";
import type { Vector3Tuple } from "three";
import type {
  IntelligenceNode,
  IntelligenceRelationship,
  Locale,
} from "./types";
import { getMessages } from "./translations";
import styles from "./Theater3DCanvas.module.css";

type Theater3DCanvasProps = {
  nodes: IntelligenceNode[];
  relationships: IntelligenceRelationship[];
  selectedNodeId: string;
  locale: Locale;
  onSelectNode: (nodeId: string) => void;
  onFallback: () => void;
};

const entityColors: Record<IntelligenceNode["type"], string> = {
  "threat-actor": "#c4a6ff",
  campaign: "#76a9ff",
  domain: "#59e1d2",
  incident: "#ffbc72",
  asset: "#9be3a7",
};

function toScenePosition(node: IntelligenceNode): Vector3Tuple {
  return [
    (node.position.x - 50) / 9,
    (48 - node.position.y) / 8,
    node.position.z * 1.5,
  ];
}

function RelationshipScene({
  nodes,
  relationships,
  selectedNodeId,
  onSelectNode,
}: Pick<
  Theater3DCanvasProps,
  "nodes" | "relationships" | "selectedNodeId" | "onSelectNode"
>) {
  const positions = useMemo(
    () => new Map(nodes.map((node) => [node.id, toScenePosition(node)])),
    [nodes],
  );

  return (
    <>
      <color attach="background" args={["#06111c"]} />
      <ambientLight intensity={1.25} />
      <pointLight position={[0, 4, 7]} intensity={24} color="#7ddde2" />
      <pointLight position={[-5, -3, 2]} intensity={9} color="#648fff" />

      {relationships.map((relationship) => {
        const start = positions.get(relationship.sourceId);
        const end = positions.get(relationship.targetId);
        if (!start || !end) return null;

        const isSelected =
          selectedNodeId === relationship.sourceId ||
          selectedNodeId === relationship.targetId;

        return (
          <Line
            key={relationship.id}
            points={[start, end]}
            color={isSelected ? "#6fe2d9" : "#3f8296"}
            lineWidth={isSelected ? 1.8 : 1}
            transparent
            opacity={isSelected ? 0.95 : 0.58}
          />
        );
      })}

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
              <span className={styles.nodeLabel}>{node.label}</span>
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
};

type ErrorBoundaryState = {
  hasError: boolean;
};

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

  render() {
    return this.state.hasError ? this.props.fallback : this.props.children;
  }
}

export function Theater3DCanvas({
  nodes,
  relationships,
  selectedNodeId,
  locale,
  onSelectNode,
  onFallback,
}: Theater3DCanvasProps) {
  const messages = getMessages(locale);
  const [canvasUnavailable, setCanvasUnavailable] = useState(false);
  const reportCanvasUnavailable = useCallback(() => setCanvasUnavailable(true), []);
  const fallback = (
    <div className={styles.fallback} role="alert">
      <p>{messages.canvasFallback}</p>
      <button type="button" onClick={onFallback}>
        {messages.switchTo2d}
      </button>
    </div>
  );

  if (canvasUnavailable) {
    return <div className={styles.canvasFrame}>{fallback}</div>;
  }

  return (
    <div className={styles.canvasFrame}>
      <SceneErrorBoundary fallback={fallback}>
        <div aria-hidden="true">
          <Canvas
            camera={{ position: [0, 0, 12], fov: 48 }}
            dpr={[1, 1.5]}
            frameloop="demand"
            gl={{ antialias: true, alpha: true, powerPreference: "low-power" }}
            fallback={<CanvasUnavailable onUnavailable={reportCanvasUnavailable} />}
          >
            <RelationshipScene
              nodes={nodes}
              relationships={relationships}
              selectedNodeId={selectedNodeId}
              onSelectNode={onSelectNode}
            />
          </Canvas>
        </div>
      </SceneErrorBoundary>
    </div>
  );
}
