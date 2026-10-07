import hashlib
import json
import random
import time

from fastapi import HTTPException

from utils.Client import Client
from utils.Logger import logger
from utils.configs import proxy_url_list
import utils.globals as globals


async def rt2ac(refresh_token, force_refresh=False):
    if not force_refresh and (refresh_token in globals.refresh_map and int(time.time()) - globals.refresh_map.get(refresh_token, {}).get("timestamp", 0) < 5 * 24 * 60 * 60):
        access_token = globals.refresh_map[refresh_token]["token"]
        # logger.info(f"refresh_token -> access_token from cache")
        return access_token
    else:
        try:
            if refresh_token.startswith("eyJhbGciOiJkaXIi"):
                access_token = await session_refresh(refresh_token)
            else:
                access_token = await chat_refresh(refresh_token)
            globals.refresh_map[refresh_token] = {"token": access_token, "timestamp": int(time.time())}
            with open(globals.REFRESH_MAP_FILE, "w") as f:
                json.dump(globals.refresh_map, f, indent=4)
            logger.info("refresh_token -> access_token successfully refreshed")
            return access_token
        except HTTPException as e:
            raise HTTPException(status_code=e.status_code, detail=e.detail)


async def session_refresh(session_token):
    session_id = hashlib.md5(session_token.encode()).hexdigest()
    proxy_url = random.choice(proxy_url_list).replace("{}", session_id) if proxy_url_list else None
    client = Client(proxy=proxy_url, impersonate='chrome120')
    try:
        cookies = {"__Secure-next-auth.session-token": session_token}
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 Safari/605.1.15",
            "Accept": "*/*",
        }
        r = await client.get("https://chatgpt.com/api/auth/session", headers=headers, cookies=cookies, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if "accessToken" in data:
                return data["accessToken"]
            raise Exception(f"No accessToken in session response: {r.text[:150]}")
        else:
            if "invalid" in r.text or r.status_code in (401, 403):
                if session_token not in globals.error_token_list:
                    globals.error_token_list.append(session_token)
                    with open(globals.ERROR_TOKENS_FILE, "a", encoding="utf-8") as f:
                        f.write(session_token + "\n")
            raise Exception(f"Session refresh failed with {r.status_code}: {r.text[:150]}")
    except Exception as e:
        logger.error(f"Failed to refresh session_token: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to refresh access_token via session_token.")
    finally:
        await client.close()
        del client


async def chat_refresh(refresh_token):
    data = {
        "client_id": "pdlLIX2Y72MIl2rhLhTE9VV9bN905kBh",
        "grant_type": "refresh_token",
        "redirect_uri": "com.openai.chat://auth0.openai.com/ios/com.openai.chat/callback",
        "refresh_token": refresh_token
    }
    session_id = hashlib.md5(refresh_token.encode()).hexdigest()
    proxy_url = random.choice(proxy_url_list).replace("{}", session_id) if proxy_url_list else None
    client = Client(proxy=proxy_url)
    try:
        r = await client.post("https://auth0.openai.com/oauth/token", json=data, timeout=15)
        if r.status_code == 200:
            access_token = r.json()['access_token']
            return access_token
        else:
            if "invalid_grant" in r.text or "access_denied" in r.text:
                if refresh_token not in globals.error_token_list:
                    globals.error_token_list.append(refresh_token)
                    with open(globals.ERROR_TOKENS_FILE, "a", encoding="utf-8") as f:
                        f.write(refresh_token + "\n")
                raise Exception(r.text)
            else:
                raise Exception(r.text[:300])
    except Exception as e:
        logger.error(f"Failed to refresh access_token `{refresh_token}`: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to refresh access_token.")
    finally:
        await client.close()
        del client
