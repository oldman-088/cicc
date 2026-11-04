"use client";

import dynamic from "next/dynamic";
import { Component, useCallback, useEffect, useState, type ReactNode } from "react";
import { RelationshipExplorer } from "./RelationshipExplorer";
import { RelationshipGraph2D } from "./RelationshipGraph2D";
import { DEMO_NODES, DEMO_RELATIONSHIPS } from "./demo-graph";
import type { Locale } from "./types";
import { isLocale } from "./types";
import { getMessages } from "./translations";
import { detectWebGLAvailability } from "./webgl-support";
import styles from "./CommandTheater.module.css";

const LazyTheater3DCanvas = dynamic(
  () =>
    import("./Theater3DCanvas").then((module) => module.Theater3DCanvas),
  {
    ssr: false,
    loading: () => (
      <div className={styles.canvasFallback} role="status">
        3D…
      </div>
    ),
  },
);

type CommandTheaterProps = {
  /** Optional locale supplied by the host application. */
  locale?: Locale;
};

type GraphicsSupport = "checking" | "available" | "unavailable";

type SceneChunkErrorBoundaryProps = {
  children: ReactNode;
  fallback: ReactNode;
  onError: () => void;
};

class SceneChunkErrorBoundary extends Component<
  SceneChunkErrorBoundaryProps,
  { hasError: boolean }
> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch() {
    this.props.onError();
  }

  render() {
    return this.state.hasError ? this.props.fallback : this.props.children;
  }
}

export function CommandTheater({ locale: initialLocale }: CommandTheaterProps) {
  const [locale, setLocale] = useState<Locale>(initialLocale ?? "en");
  const [graphicsSupport, setGraphicsSupport] = useState<GraphicsSupport>("checking");
  const [view, setView] = useState<"2d" | "3d">("2d");
  const [selectedNodeId, setSelectedNodeId] = useState(DEMO_NODES[0]?.id ?? "");
  const messages = getMessages(locale);
  const handleGraphicsFallback = useCallback(() => {
    setGraphicsSupport("unavailable");
    setView("2d");
  }, []);

  useEffect(() => {
    if (initialLocale) {
      setLocale(initialLocale);
      return;
    }

    const documentLocale = document.documentElement.lang.toLowerCase().split("-")[0];
    if (isLocale(documentLocale)) setLocale(documentLocale);
  }, [initialLocale]);

  useEffect(() => {
    setGraphicsSupport(detectWebGLAvailability() ? "available" : "unavailable");
  }, []);

  const graphicsMessage =
    graphicsSupport === "checking"
      ? messages.graphicsChecking
      : graphicsSupport === "available"
        ? messages.graphicsReady
        : messages.graphicsUnavailable;

  return (
    <main
      className={styles.shell}
      lang={locale}
      dir={locale === "en" ? "ltr" : "rtl"}
      aria-labelledby="command-theater-title"
    >
      <div className={styles.console}>
        <header className={styles.header}>
          <div className={styles.brandBlock}>
            <p className={styles.eyebrow}>{messages.eyebrow}</p>
            <h1 id="command-theater-title">{messages.title}</h1>
            <p className={styles.subtitle}>{messages.subtitle}</p>
          </div>

          <label className={styles.localeControl}>
            <span>{messages.language}</span>
            <select
              value={locale}
              onChange={(event) => setLocale(event.target.value as Locale)}
            >
              <option value="en">English</option>
              <option value="ar">العربية</option>
              <option value="fa">فارسی</option>
            </select>
          </label>
        </header>

        <div className={styles.demoBanner} role="note">
          <span className={styles.demoBadge}>{messages.demoBadge}</span>
          <span>{messages.demoDescription}</span>
        </div>

        <div className={styles.statsRow}>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{DEMO_NODES.length}</span>
            <span className={styles.statLabel}>{messages.entitiesCount}</span>
          </div>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{DEMO_RELATIONSHIPS.length}</span>
            <span className={styles.statLabel}>{messages.relationshipsCount}</span>
          </div>
        </div>

        <div className={styles.contentGrid}>
          <section className={styles.stage} aria-labelledby="relationship-theater-heading">
            <div className={styles.stageHeader}>
              <h2 id="relationship-theater-heading">{messages.stageTitle}</h2>
              <div className={styles.viewControls} role="group" aria-label={messages.viewMode}>
                <button
                  type="button"
                  className={view === "2d" ? styles.viewButtonActive : styles.viewButton}
                  aria-pressed={view === "2d"}
                  onClick={() => setView("2d")}
                >
                  {messages.view2d}
                </button>
                <button
                  type="button"
                  className={view === "3d" ? styles.viewButtonActive : styles.viewButton}
                  aria-pressed={view === "3d"}
                  aria-describedby="graphics-support-status"
                  disabled={graphicsSupport !== "available"}
                  onClick={() => setView("3d")}
                >
                  {messages.view3d}
                </button>
              </div>
            </div>

            <p id="graphics-support-status" className={styles.graphicsStatus} role="status" aria-live="polite">
              {graphicsMessage}
            </p>

            <div className={styles.visualization}>
              {view === "2d" ? (
                <RelationshipGraph2D
                  nodes={DEMO_NODES}
                  relationships={DEMO_RELATIONSHIPS}
                  selectedNodeId={selectedNodeId}
                  locale={locale}
                />
              ) : (
                <div className={styles.canvas3dFrame}>
                  <SceneChunkErrorBoundary
                    onError={handleGraphicsFallback}
                    fallback={
                      <div className={styles.canvasFallback} role="alert">
                        <p>{messages.canvasFallback}</p>
                        <button
                          className={styles.fallbackButton}
                          type="button"
                          onClick={handleGraphicsFallback}
                        >
                          {messages.switchTo2d}
                        </button>
                      </div>
                    }
                  >
                    <LazyTheater3DCanvas
                      nodes={DEMO_NODES}
                      relationships={DEMO_RELATIONSHIPS}
                      selectedNodeId={selectedNodeId}
                      locale={locale}
                      onSelectNode={setSelectedNodeId}
                      onFallback={handleGraphicsFallback}
                    />
                  </SceneChunkErrorBoundary>
                </div>
              )}
            </div>
          </section>

          <RelationshipExplorer
            nodes={DEMO_NODES}
            relationships={DEMO_RELATIONSHIPS}
            selectedNodeId={selectedNodeId}
            locale={locale}
            onSelectNode={setSelectedNodeId}
          />
        </div>

        <p className={styles.footerNote}>{messages.demoDescription}</p>
      </div>
    </main>
  );
}
