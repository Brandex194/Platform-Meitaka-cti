def error_response(code: str, message: str, detail: dict = {}) -> dict:
    return {"error": {"code": code, "message": message, "detail": detail}}
