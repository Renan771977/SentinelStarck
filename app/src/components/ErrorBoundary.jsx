import { Component } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";

const C = {
  panel: "#0F141D", raised: "#161D29", line: "#222C3C",
  text: "#E8ECF4", dim: "#9AA5B8", faint: "#6B7688", cyan: "#00C2FF",
  critical: "#FF4D6D",
};
const sans = { fontFamily: "Inter,-apple-system,'Segoe UI',sans-serif" };
const mono = { fontFamily: "'JetBrains Mono','SFMono-Regular',Consolas,monospace" };

/**
 * Captura erro de renderização de qualquer componente abaixo dele.
 *
 * Sem isto, um erro de JavaScript num componente derruba a árvore React inteira
 * e a janela fica BRANCA e muda — o pior tipo de falha, porque não diz nada. O
 * boundary troca a tela morta por uma mensagem com o erro e um botão de
 * recuperar. É a diferença entre "o app quebrou" e "esta parte teve um
 * problema, o resto continua".
 *
 * Error boundary PRECISA ser class component: é a única API que o React oferece
 * para capturar erro de render (getDerivedStateFromError / componentDidCatch).
 * Não há equivalente com hooks.
 *
 * Props:
 *   - `scope`: nome legível da região protegida, mostrado na mensagem.
 *   - `onReset`: opcional; chamado quando a pessoa clica em "tentar de novo".
 *   - `resetKey`: quando muda, o boundary se recupera sozinho. Passe a aba
 *     atual aqui, para trocar de tela limpar um erro preso.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Registra no console do WebView para diagnóstico. Não engole o erro: só
    // impede que ele derrube o app.
    console.error(`[ErrorBoundary${this.props.scope ? " · " + this.props.scope : ""}]`, error, info?.componentStack);
  }

  componentDidUpdate(prev) {
    // Recuperação automática ao trocar de contexto (ex.: mudar de aba). Sem
    // isto, um erro numa tela ficaria preso mesmo depois de sair dela.
    if (this.state.error && prev.resetKey !== this.props.resetKey) {
      this.setState({ error: null });
    }
  }

  reset = () => {
    this.setState({ error: null });
    this.props.onReset?.();
  };

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="rounded-lg p-6" style={{ background: C.panel, border: `1px solid ${C.critical}44` }}>
        <div className="flex items-start gap-3">
          <div className="rounded-md p-2 shrink-0" style={{ background: `${C.critical}18` }}>
            <AlertTriangle size={18} style={{ color: C.critical }} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium" style={{ ...sans, color: C.text }}>
              Algo deu errado{this.props.scope ? ` em ${this.props.scope}` : " nesta parte"}
            </p>
            <p className="text-sm mt-1" style={{ ...sans, color: C.dim, maxWidth: "70ch" }}>
              O resto do aplicativo continua funcionando. Você pode tentar recarregar esta
              seção. Se o problema persistir, reinicie o aplicativo.
            </p>
            <div className="rounded-md p-2.5 mt-3" style={{ background: C.raised, border: `1px solid ${C.line}` }}>
              <p style={{ ...mono, color: C.faint, fontSize: 12, wordBreak: "break-word" }}>
                {String(error.message || error)}
              </p>
            </div>
            <button onClick={this.reset}
              className="inline-flex items-center gap-1.5 rounded-md px-3 h-8 text-sm mt-3"
              style={{ ...sans, background: C.raised, color: C.text, border: `1px solid ${C.line}` }}>
              <RotateCw size={13} /> Tentar de novo
            </button>
          </div>
        </div>
      </div>
    );
  }
}