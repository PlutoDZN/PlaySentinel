import asyncio
from typing import Any

import aiohttp


class PlaySentinelApiClient:
    def __init__(
        self,
        api_url: str,
        api_key: str | None = None,
        timeout_seconds: int = 20,
        retries: int = 2,
        reset_url: str | None = None,
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        self.reset_url = reset_url or ""
        self._session: aiohttp.ClientSession | None = None

    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    async def analyze_message(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        session = await self.get_session()

        for attempt in range(self.retries + 1):
            try:
                async with session.post(self.api_url, json=payload, headers=headers) as response:
                    text = await response.text()

                    if response.status != 200:
                        print(f"[API ERROR] status={response.status} body={text[:500]}")

                        if response.status in {429, 500, 502, 503, 504} and attempt < self.retries:
                            await asyncio.sleep(1.5 * (attempt + 1))
                            continue

                        return None

                    try:
                        data = await response.json()
                    except Exception:
                        print(f"[API ERROR] invalid JSON body={text[:500]}")
                        return None

                    if not isinstance(data, dict):
                        print("[API ERROR] API response was not a JSON object.")
                        return None

                    return data

            except asyncio.TimeoutError:
                print("[API ERROR] Request timed out.")
                if attempt < self.retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                return None
            except aiohttp.ClientError as exc:
                print(f"[API ERROR] Client error: {exc}")
                if attempt < self.retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
                    continue
                return None
            except Exception as exc:
                print(f"[API ERROR] Unexpected error: {exc}")
                return None

        return None

    async def reset_conversation_state(
        self,
        user_id: str,
        target_id: str,
        platform: str = "discord",
    ) -> bool | None:
        if not self.reset_url:
            return None

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        payload = {
            "user_id": user_id,
            "target_id": target_id,
            "platform": platform,
        }

        session = await self.get_session()
        try:
            async with session.post(self.reset_url, json=payload, headers=headers) as response:
                text = await response.text()
                if response.status not in {200, 204}:
                    print(f"[API RESET ERROR] status={response.status} body={text[:500]}")
                    return False
                print(f"[API RESET OK] user_id={user_id} target_id={target_id}")
                return True
        except Exception as exc:
            print(f"[API RESET ERROR] {exc}")
            return False