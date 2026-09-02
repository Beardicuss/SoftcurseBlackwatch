import { ChevronDown, CircleHelp, ExternalLink, Info, ShieldCheck } from 'lucide-react';
import { motion } from 'framer-motion';

interface FaqItem {
  question: string;
  answer: string;
}

interface FaqGroup {
  title: string;
  items: FaqItem[];
}

const groups: FaqGroup[] = [
  {
    title: 'WHAT BLACKWATCH IS',
    items: [
      { question: 'What is Softcurse Blackwatch?', answer: 'Softcurse Blackwatch is a local Windows monitoring and investigation companion for home users. It inventories running processes and TCP connections, enriches them with identity and signature information, and presents explainable heuristic evidence so you can review unusual activity.' },
      { question: 'Who created Blackwatch?', answer: 'Blackwatch is created and maintained by Softcurse. Version 0.1.0 Early Alpha is the first public home-user preview of the Softcurse Blackwatch project.' },
      { question: 'Is Blackwatch an antivirus replacement?', answer: 'No. Blackwatch complements Microsoft Defender and other reputable antivirus products; it does not replace them. It has no kernel driver, on-access file scanner, malware-signature engine, or cloud detonation service.' },
      { question: 'Does Blackwatch guarantee that my computer is clean?', answer: 'No security tool can guarantee that. “No threats detected” means Blackwatch found no process evidence meeting its current alert rules during the latest successful scan. It is not proof that every file, driver, browser extension, or offline component is safe.' },
    ],
  },
  {
    title: 'MONITORING AND DETECTION',
    items: [
      { question: 'What does Blackwatch monitor?', answer: 'It monitors CPU and memory utilization, running processes, process identity and publisher metadata, parent relationships, active/listening TCP connections, owning processes, remote endpoints, and available reverse-DNS names.' },
      { question: 'How often does it scan?', answer: 'The main process and network collection cycle runs approximately every five seconds. When WMI process-start events are unavailable, a non-admin one-second polling fallback detects newly created processes and requests a guarded scan.' },
      { question: 'How are threats scored?', answer: 'Blackwatch combines versioned, explainable observations such as suspicious names or paths, unsigned identity, unusual parent relationships, command-line indicators, resource behavior, and corroborating network evidence. A score is evidence for review—not a malware verdict.' },
      { question: 'Why can a legitimate program appear suspicious?', answer: 'Heuristics trade certainty for visibility. Developer tools, portable utilities, miners, automation software, remote-access tools, and unsigned applications can resemble malicious behavior. Review the path, publisher, evidence, and context before acting.' },
      { question: 'What does connection confidence mean?', answer: 'Network confidence reflects corroborating evidence associated with the owning process or a verified reputation indicator. “None” means Blackwatch has not established suspicious evidence for that connection; it does not certify the remote host as trustworthy.' },
    ],
  },
  {
    title: 'ACTIONS AND SAFETY',
    items: [
      { question: 'What does Scan Now do?', answer: 'Scan Now requests an immediate guarded collection cycle. It refreshes processes, scoring, network evidence, system telemetry, and the last-successful-scan timestamp. It does not delete or terminate anything.' },
      { question: 'What is Dry-Run Mode?', answer: 'Dry-run mode keeps response actions non-destructive. Purge records what it would target but does not terminate processes. It is enabled by default and is strongly recommended while you learn how Blackwatch classifies your system.' },
      { question: 'What does Purge do?', answer: 'The current v1 Purge workflow targets only processes classified at high severity or above. Blackwatch shows a native confirmation, revalidates the exact PID/name/start-time identity, protects critical Windows processes, requires a short-lived authorization, and journals the result. Never approve a target you do not understand.' },
      { question: 'What is a Trusted Application?', answer: 'A trusted application is bound to the selected executable’s canonical path and SHA-256 hash; signed files can also be bound to the publisher certificate. It is not a loose filename exclusion. Updating the application may change its hash and require a new trust decision.' },
      { question: 'Does Blackwatch block network traffic?', answer: 'No. This Early Alpha observes and explains TCP activity but does not modify Windows Firewall rules, intercept packets, or block remote endpoints.' },
    ],
  },
  {
    title: 'PRIVACY, LOGS, AND SUPPORT',
    items: [
      { question: 'Does Blackwatch send data to Softcurse?', answer: 'No. This Early Alpha has no Softcurse backend, account, cloud telemetry, or in-app updater. Monitoring and configuration remain local to this computer.' },
      { question: 'Where are settings and logs stored?', answer: 'Blackwatch stores its local configuration, logs, action journal, and quarantine-related state under the current user’s Local AppData SoftcurseBlackwatch directory. The program itself installs per-user under Local AppData Programs by default.' },
      { question: 'What is stored in logs?', answer: 'Logs contain operational events, collector health, scan summaries, detections, and confirmed response outcomes. Common secrets, URL queries, user-profile paths, and line-break injection are redacted before memory and disk storage. Logs rotate at 5 MB and are retained for up to 14 days within a 20 MB total budget.' },
      { question: 'What is in the diagnostic ZIP?', answer: 'Only a bounded health summary and retained Blackwatch-owned logs are included. Historical lines are redacted again during export. The ZIP is created only after you explicitly choose a destination; it is not uploaded automatically.' },
      { question: 'Why may Windows warn about the installer?', answer: 'The v1 installer may be unsigned, so Windows SmartScreen can show an unknown-publisher warning. Download only from the official Softcurse Blackwatch page and compare the published SHA-256 checksum before running it.' },
      { question: 'How do I report a problem?', answer: 'Export a redacted diagnostic ZIP from Settings, describe what you expected and what happened, and include the Blackwatch version. Review the ZIP yourself before sharing it. Never send sensitive files or credentials.' },
    ],
  },
];

export function FaqPage() {
  return (
    <div className="flex-1 flex flex-col p-5 overflow-hidden">
      <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-3 mb-4">
        <div className="flex items-center justify-center w-6 h-6 border border-[var(--cyan)]"><CircleHelp size={15} /></div>
        <div>
          <h2 className="text-lg font-['Orbitron'] font-bold text-[var(--cyan)] text-glow-cyan tracking-wider">FAQ / ABOUT</h2>
          <p className="text-[10px] text-[var(--text-dim)] font-['Share_Tech_Mono'] tracking-wider">CLEAR ANSWERS. LOCAL SECURITY. INFORMED DECISIONS.</p>
        </div>
      </motion.div>

      <div className="flex-1 overflow-auto pr-3 space-y-4">
        <section className="tech-card p-5 border-[rgba(0,240,255,0.45)] relative overflow-hidden">
          <div className="absolute inset-y-0 left-0 w-1 bg-[var(--cyan)] shadow-[0_0_14px_var(--cyan)]" />
          <div className="flex items-start justify-between gap-6">
            <div className="flex gap-3">
              <ShieldCheck className="text-[var(--cyan)] shrink-0 mt-0.5" size={24} />
              <div>
                <h3 className="text-sm text-white font-['Orbitron'] tracking-wider">SOFTCURSE BLACKWATCH 0.1.0 · EARLY ALPHA</h3>
                <p className="text-xs text-[var(--text-primary)] mt-2 max-w-3xl leading-relaxed">A privacy-first Windows process and network monitoring companion created by <span className="text-[var(--cyan)]">Softcurse</span> for home users. Blackwatch helps you investigate evidence; it does not pretend that a heuristic score is certainty.</p>
              </div>
            </div>
            <div className="text-right shrink-0 font-['Share_Tech_Mono'] text-[10px]">
              <div className="text-[var(--cyan)] flex items-center justify-end gap-1"><ExternalLink size={10} /> OFFICIAL PROJECT</div>
              <div className="text-[var(--text-dim)] mt-1">softcursesystems.pages.dev/lab/blackwatch</div>
            </div>
          </div>
        </section>

        <div className="flex gap-2 items-start border border-[rgba(255,170,0,0.3)] bg-[rgba(255,170,0,0.05)] px-4 py-3 text-[11px] text-[#ffc266] font-['Share_Tech_Mono']">
          <Info size={15} className="shrink-0" /> Keep Microsoft Defender enabled. Investigate evidence before using response actions, and keep Dry-Run Mode enabled until you understand the results.
        </div>

        {groups.map(group => (
          <section key={group.title}>
            <h3 className="text-xs font-['Orbitron'] text-[var(--cyan)] tracking-[0.14em] mb-2">{group.title}</h3>
            <div className="space-y-2">
              {group.items.map((item, index) => (
                <details key={item.question} className="faq-item tech-card group" open={index === 0 && group.title === 'WHAT BLACKWATCH IS'}>
                  <summary className="cursor-pointer list-none flex items-center justify-between gap-4 px-4 py-3 text-xs text-[var(--text-primary)] font-['Share_Tech_Mono'] hover:text-[var(--cyan)] focus-visible:outline focus-visible:outline-1 focus-visible:outline-[var(--cyan)]">
                    <span>{item.question}</span>
                    <ChevronDown size={14} className="text-[var(--cyan)] shrink-0 transition-transform group-open:rotate-180" />
                  </summary>
                  <div className="px-4 pb-4 pt-1 border-t border-[rgba(0,240,255,0.08)] text-[11px] leading-relaxed text-[var(--text-dim)]">{item.answer}</div>
                </details>
              ))}
            </div>
          </section>
        ))}

        <footer className="text-center py-4 border-t border-[rgba(0,240,255,0.15)] font-['Share_Tech_Mono']">
          <div className="text-[var(--cyan)] text-xs tracking-[0.2em]">CREATED BY SOFTCURSE</div>
          <div className="text-[9px] text-[var(--text-dim)] mt-1">SOFTCURSE BLACKWATCH · HOME PREVIEW · VERSION 0.1.0 EARLY ALPHA</div>
        </footer>
      </div>
    </div>
  );
}
