import { CommandTheater } from "../components/command-theater/CommandTheater";
import styles from "../components/command-theater/CommandTheater.module.css";

export default function HomePage() {
  return (
    <main className={styles.pageHost}>
      <CommandTheater demoMode={process.env.NODE_ENV === "development"} />
    </main>
  );
}
