#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analizador de ciberseguridad asistido por IA (Groq)
Escanea puertos, detecta servicios, resuelve DNS inverso y consulta WHOIS.
Uso: python3 analizador_seguridad_ia.py
"""

import os
import json
import socket
import subprocess
import re
import logging
from typing import List, Dict, Optional, Any
from dotenv import load_dotenv
from groq import Groq

# ------------------------------------------------------------
# CONFIGURACIÓN Y LOGGING
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv(dotenv_path="../.env")  # Ajusta si el .env está en otra ruta
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    raise ValueError("No se encontró GROQ_API_KEY. Crea el archivo .env con: GROQ_API_KEY='gsk_tu_clave'")

# ------------------------------------------------------------
# FUNCIONES DE UTILIDAD
# ------------------------------------------------------------
def puerto_abierto(ip: str, puerto: int, timeout: float = 1.0) -> bool:
    """Comprueba si un puerto TCP está abierto."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, puerto))
    sock.close()
    return result == 0

def obtener_banner(ip: str, puerto: int, timeout: float = 2.0) -> Optional[str]:
    """Intenta obtener el banner de un servicio TCP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, puerto))
        # Enviar una petición genérica o específica según el puerto
        if puerto == 80:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif puerto == 443:
            # Para HTTPS, el banner no es fácil; devolvemos un marcador
            return "SSL/TLS (no se pudo leer banner sin handshake)"
        elif puerto == 22:
            sock.send(b"SSH-2.0-Client\r\n")
        else:
            sock.send(b"\r\n")
        banner = sock.recv(256).decode(errors='ignore').strip()
        sock.close()
        return banner[:200]  # truncar
    except Exception as e:
        logger.debug(f"Error obteniendo banner en puerto {puerto}: {e}")
        return None

# ------------------------------------------------------------
# FUNCIONES PRINCIPALES DE ANÁLISIS
# ------------------------------------------------------------
def resolver_ptr(ip: str) -> Optional[str]:
    """Resolución DNS inversa (PTR)."""
    try:
        nombre = socket.gethostbyaddr(ip)[0]
        return nombre
    except socket.herror:
        return None
    except Exception as e:
        logger.error(f"Error en resolución PTR: {e}")
        return None

def consultar_whois(objetivo: str) -> Dict[str, Any]:
    """
    Consulta WHOIS para una IP o dominio.
    Retorna un diccionario con campos relevantes.
    """
    resultado = {
        "org_name": None,
        "net_range": None,
        "abuse_email": None,
        "country": None,
        "raw": None
    }
    try:
        proc = subprocess.run(
            ["whois", objetivo],
            capture_output=True,
            text=True,
            timeout=10
        )
        salida = proc.stdout
        resultado["raw"] = salida[:500]  # guardar parte de la salida

        # Patrones comunes en WHOIS
        patrones = {
            "org_name": r"(OrgName|organisation|owner):\s*(.+)",
            "net_range": r"(NetRange|inetnum):\s*(.+)",
            "abuse_email": r"(OrgAbuseEmail|abuse-mailbox):\s*(.+)",
            "country": r"(Country|country):\s*(.+)"
        }
        for key, pattern in patrones.items():
            match = re.search(pattern, salida, re.IGNORECASE)
            if match:
                resultado[key] = match.group(2).strip()
    except Exception as e:
        logger.error(f"Error en consulta WHOIS: {e}")
        resultado["error"] = str(e)
    return resultado

def escanear_puertos_completo(
    ip: str,
    rango_puertos: str = "20-1024",
    timeout: float = 1.0
) -> Dict[str, Any]:
    """
    Escanea puertos, obtiene banners y devuelve estructura completa.
    """
    resultados = {
        "ip": ip,
        "ptr": resolver_ptr(ip),
        "whois": consultar_whois(ip),
        "puertos_abiertos": []
    }
    try:
        inicio, fin = map(int, rango_puertos.split('-'))
        if fin > 65535:
            fin = 65535
            logger.warning(f"Limitando rango a 65535")
        logger.info(f"Iniciando escaneo de {ip} en puertos {inicio}-{fin}")
        for puerto in range(inicio, fin + 1):
            if puerto_abierto(ip, puerto, timeout):
                banner = obtener_banner(ip, puerto, timeout)
                resultados["puertos_abiertos"].append({
                    "puerto": puerto,
                    "banner": banner
                })
                logger.info(f"Puerto {puerto} abierto - Banner: {banner[:50] if banner else 'N/A'}")
    except Exception as e:
        logger.error(f"Error en escaneo: {e}")
        resultados["error"] = str(e)
    return resultados

# ------------------------------------------------------------
# DEFINICIÓN DE HERRAMIENTAS PARA GROQ (FUNCTION CALLING)
# ------------------------------------------------------------
herramientas = [
    {
        "type": "function",
        "function": {
            "name": "escanear_puertos_completo",
            "description": (
                "Escanea una dirección IP para detectar puertos abiertos, "
                "obtiene banners de servicios, resuelve el nombre DNS inverso "
                "y consulta información WHOIS."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Dirección IP a analizar (ej. '45.33.32.156')"
                    },
                    "rango_puertos": {
                        "type": "string",
                        "description": "Rango en formato 'inicio-fin', por defecto '20-1024'",
                        "default": "20-1024"
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout de conexión en segundos",
                        "default": 1.0
                    }
                },
                "required": ["ip"]
            }
        }
    }
]

cliente = Groq(api_key=GROQ_API_KEY)

# ------------------------------------------------------------
# AGENTE INTELIGENTE CON GROQ
# ------------------------------------------------------------
def ejecutar_agente(consulta_usuario: str) -> str:
    """Envía la consulta a Groq y ejecuta las herramientas necesarias."""
    system_prompt = {
        "role": "system",
        "content": (
            "Eres un analista de ciberseguridad. Tienes acceso a la herramienta 'escanear_puertos_completo' "
            "que escanea puertos, banners, PTR y WHOIS. Cuando el usuario pida analizar una IP, llama a esa herramienta. "
            "Luego, con los resultados, genera un informe en español que incluya:\n"
            "- IP analizada\n"
            "- Nombre inverso (si existe)\n"
            "- Propietario y país (según WHOIS)\n"
            "- Lista de puertos abiertos y sus servicios (interpretando banners)\n"
            "- Correo de abuso si está disponible\n"
            "- Clasificación de riesgo: BAJO si solo servicios comunes (HTTP, SSH), MEDIO si hay FTP, Telnet, etc., "
            "ALTO si se detectan servicios vulnerables o banners sospechosos.\n"
            "Sé conciso y profesional. No incluyas sugerencias de usar otras herramientas como nmap."
        )
    }
    mensajes = [system_prompt, {"role": "user", "content": consulta_usuario}]

    # Primera llamada a Groq
    respuesta = cliente.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=mensajes,
        tools=herramientas,
        tool_choice="auto"
    )
    msg = respuesta.choices[0].message
    tool_calls = msg.tool_calls

    if not tool_calls:
        return msg.content

    # Ejecutar la(s) herramienta(s) solicitadas
    mensajes.append(msg)
    funciones_disponibles = {
        "escanear_puertos_completo": escanear_puertos_completo
    }
    for tool_call in tool_calls:
        func_name = tool_call.function.name
        func = funciones_disponibles.get(func_name)
        if func:
            args = json.loads(tool_call.function.arguments)
            logger.info(f"Ejecutando {func_name} con argumentos {args}")
            resultado = func(**args)
            mensajes.append({
                "tool_call_id": tool_call.id,
                "role": "tool",
                "name": func_name,
                "content": json.dumps(resultado, indent=2)
            })
        else:
            logger.warning(f"Función {func_name} no encontrada")

    # Segunda llamada a Groq para el informe final
    final = cliente.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=mensajes
    )
    return final.choices[0].message.content

# ------------------------------------------------------------
# ENTRADA PRINCIPAL
# ------------------------------------------------------------
if __name__ == "__main__":
    print("=== Analizador de Ciberseguridad Asistido por IA ===\n")
    consulta = input("¿Qué IP o dominio deseas analizar? ").strip()
    if not consulta:
        consulta = "45.33.32.156"
    print("\n--- Enviando solicitud al agente IA ---\n")
    respuesta = ejecutar_agente(consulta)
    print("\n--- INFORME GENERADO POR IA ---\n")
    print(respuesta)
