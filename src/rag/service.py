import uuid
from .lc_service import ChatService

_chat = ChatService()


class RagService:
    def analyze(
        self,
        alert_text: str,
        k: int = 5,
        source: str | None = None,
        template_name: str = "basic",
    ) -> dict:
        session_id = str(uuid.uuid4())
        result = _chat.chat(session_id, alert_text, source, k, template_name)
        _chat.clear(session_id)
        return result
    
    
