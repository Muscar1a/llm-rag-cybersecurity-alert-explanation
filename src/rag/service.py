import uuid
from .lc_service import ChatService

_chat = ChatService()


class RagService:
    def analyze(self, alert_text: str, k: int, source: str | None) -> dict:
        session_id = str(uuid.uuid4())
        result = _chat.chat(session_id, alert_text, source, k)
        _chat.clear(session_id)
        return result
    
    
