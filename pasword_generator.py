# password_generator.py
# Gerador de senhas seguro usando 'secrets' (criptograficamente forte).
# Uso (terminal):
#   python password_generator.py --length 16 --digits --symbols --count 3 --no-ambiguous

import argparse
import secrets
import string
from typing import List

AMBIGUOS = set("Il1O0B8S5Z2(){}[]/\\'\"`,;:.<>")

def build_charset(use_lower: bool, use_upper: bool, use_digits: bool, use_symbols: bool, no_ambiguous: bool) -> List[str]:
    charset = []
    if use_lower:
        charset.extend(string.ascii_lowercase)
    if use_upper:
        charset.extend(string.ascii_uppercase)
    if use_digits:
        charset.extend(string.digits)
    if use_symbols:
        # símbolos comuns e seguros
        charset.extend("!@#$%^&*_-+=?")
    if no_ambiguous:
        charset = [c for c in charset if c not in AMBIGUOS]
    return charset

def generate_password(length: int, use_lower=True, use_upper=True, use_digits=True, use_symbols=True, no_ambiguous=False) -> str:
    # Garante pelo menos um caractere de cada categoria selecionada.
    pools = []
    if use_lower:
        pools.append([c for c in string.ascii_lowercase if not no_ambiguous or c not in AMBIGUOS])
    if use_upper:
        pools.append([c for c in string.ascii_uppercase if not no_ambiguous or c not in AMBIGUOS])
    if use_digits:
        pools.append([c for c in string.digits if not no_ambiguous or c not in AMBIGUOS])
    if use_symbols:
        pools.append([c for c in "!@#$%^&*_-+=?" if not no_ambiguous or c not in AMBIGUOS])

    if not pools:
        raise ValueError("Selecione pelo menos um tipo de caractere.")

    if length < len(pools):
        raise ValueError(f"Comprimento mínimo é {len(pools)} para incluir todas as categorias selecionadas.")

    # Começa garantindo 1 caractere de cada pool
    password_chars = [secrets.choice(pool) for pool in pools]

    # Completa o restante com o charset combinado
    charset = [c for pool in pools for c in pool]
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(charset) for _ in range(remaining)]

    # Embaralha de forma segura
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)

def main():
    parser = argparse.ArgumentParser(description="Gerador de senhas seguro (usa secrets).")
    parser.add_argument("--length", type=int, default=12, help="Tamanho da senha (padrão: 12).")
    parser.add_argument("--no-lower", action="store_true", help="Não usar letras minúsculas.")
    parser.add_argument("--no-upper", action="store_true", help="Não usar letras maiúsculas.")
    parser.add_argument("--digits", action="store_true", help="Incluir dígitos (0-9).")
    parser.add_argument("--symbols", action="store_true", help="Incluir símbolos (!@#$...).")
    parser.add_argument("--no-ambiguous", action="store_true", help="Evitar caracteres ambíguos (ex.: I, l, 1, O, 0).")
    parser.add_argument("--count", type=int, default=1, help="Quantidade de senhas para gerar (padrão: 1).")

    args = parser.parse_args()

    use_lower = not args.no_lower
    use_upper = not args.no_upper
    use_digits = args.digits
    use_symbols = args.symbols

    try:
        for _ in range(max(1, args.count)):
            print(generate_password(
                length=args.length,
                use_lower=use_lower,
                use_upper=use_upper,
                use_digits=use_digits,
                use_symbols=use_symbols,
                no_ambiguous=args.no_ambiguous
            ))
    except ValueError as e:
        print(f"Erro: {e}")

if _name_ == "_main_":
    main()
