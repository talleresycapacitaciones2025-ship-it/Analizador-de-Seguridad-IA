# Analizador de Ciberseguridad con IA (Groq + Python)

Escáner de puertos, detección de servicios, WHOIS y resolución inversa asistido por Groq.

## Características
- Escaneo de puertos TCP
- Captura de banners
- Resolución DNS inversa (PTR)
- Consulta WHOIS de IP/dominio
- Integración con Groq (function calling) para orquestación e informes

## Requisitos
- Python 3.8+
- Clave de API de Groq (https://console.groq.com)

## Instalación
bash
git clone https://github.com/tu-usuario/analizador-seguridad-ia.git
cd analizador-seguridad-ia
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo 'GROQ_API_KEY="gsk_..."' > .env

---

## Uso
python analizador_seguridad_ia.py

---

## Nota legal
Solo usa este script contra sistemas con permiso explícito.

