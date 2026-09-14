import { Component } from "react";
import { AlertTriangle, RotateCw } from "lucide-react";
import { T, SEVERITY, sans, mono } from "../lib/theme";


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
      <div className="rounded-lg p-6" style={{ background: T.surface, border: `1px solid ${SEVERITY.critical}44` }}>
        <div className="flex items-start gap-3">
          <div className="rounded-md p-2 shrink-0" style={{ background: `${SEVERITY.critical}18` }}>
            <AlertTriangle size={18} style={{ color: SEVERITY.critical }} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium" style={{ ...sans, color: T.text }}>
              Algo deu errado{this.props.scope ? ` em ${this.props.scope}` : " nesta parte"}
            </p>
            <p className="text-sm mt-1" style={{ ...sans, color: T.dim, maxWidth: "70ch" }}>
              O resto do aplicativo continua funcionando. Você pode tentar recarregar esta
              seção. Se o problema persistir, reinicie o aplicativo.
            </p>
            <div className="rounded-md p-2.5 mt-3" style={{ background: T.raised, border: `1px solid ${T.border}` }}>
              <p style={{ ...mono, color: T.faint, fontSize: 12, wordBreak: "break-word" }}>
                {String(error.message || error)}
              </p>
            </div>
            <button onClick={this.reset}
              className="inline-flex items-center gap-1.5 rounded-md px-3 h-8 text-sm mt-3"
              style={{ ...sans, background: T.raised, color: T.text, border: `1px solid ${T.border}` }}>
              <RotateCw size={13} /> Tentar de novo
            </button>
          </div>
        </div>
      </div>
    );
  }
}