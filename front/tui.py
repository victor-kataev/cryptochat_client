import asyncio
import websockets

from textual.screen import Screen
from textual.message import Message
from textual.app import App
from textual.widgets import Static, Label, Button, Input, Footer, Header
from textual.containers import HorizontalScroll, VerticalScroll
from client.api import Client


dummy_chats = {
    "vovan": "hey, how you doin?",
    "pahan": "hey, how you doin?",
    "kran": "hey, how you doin?",
    "drabadan": "hey, how you doin?",
    "toksikoman": "hey, how you doin?",
}


# class NewChatMessage(Message):
#     def __init__(self, content):
#         super().__init__()
#         self.content = content


class ChatScreen(Screen):
    BINDINGS = [
        ("escape", "app.pop_screen", "back")
    ]

    def __init__(self, client: Client, sq: asyncio.Queue, uid: str):
        super().__init__()
        self.client = client
        self.sender_queue = sq
        self.uid = uid
    
    def compose(self):
        yield Static(f"You are talking with {self.uid}")
        self.scroll_container = VerticalScroll()
        with self.scroll_container:
            self.chat_window = Static(f"", id="chat-window-id")
            yield self.chat_window
        yield self.scroll_container
        self.message_input = Input(placeholder="Message...")
        yield self.message_input

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        user_text = event.value
        if not event.value:
            return
        await self.sender_queue.put(user_text)
        self.message_input.clear()

    # def on_new_chat_message(self, message: NewChatMessage):
    #     print("called")
    #     output = self.query_one("#chat-window-id", Static)
    #     current_content = str(output.content)
    #     output.update(f"{current_content}\n{message.content}")


class TextualUI(App):
    CSS_PATH = "styles.tcss"
    BINDINGS = [
        ("escape", "quit", "quit")
    ]

    def __init__(self, client: Client):
        super().__init__()
        self.client = client
        self.sender_queue = asyncio.Queue()
        self.receiver_queue = asyncio.Queue()

    def compose(self):
        yield Header()

        yield Button("chat", id="chat-button")

        # self.token = Static(f"Your session token: [bold white]{self.client.session.session_token}[/bold white]")
        # yield self.token

        for k, v in dummy_chats.items():
            with HorizontalScroll(classes="conversation", id=f"{k}"):
                self.nickname = Static(f"[bold]{k}[/bold]", classes="nickname")
                yield self.nickname
                yield Static(f"{v}", classes="last-message-quick-access")

            # with HorizontalScroll(classes="conversation", id=f"{self.client.uid}"):
            #     self.nickname = Static(f"[bold]{self.client.uid}[/bold]", classes="nickname")
            #     yield self.nickname
            #     yield Static(f"{self.client.session.session_token}", classes="last-message-quick-access")
                
        yield Footer()

    def on_button_pressed(self, event):
        print("button id", event.button.id)
        if event.button.id == "chat-button":
            self.push_screen("chatscreen")

    def on_click(self, event):
        current = event.widget
        while current is not None:
            if isinstance(current, HorizontalScroll) and "conversation" in current.classes:
                nickname_widget = current.query_one(".nickname", Static)
                uid = str(nickname_widget.content)
                self.push_screen(ChatScreen(self.client, self.sender_queue, uid))
                break
            current = current.parent

    async def on_mount(self):
        async def websocket_handler():
            async with websockets.connect(f"ws://localhost:8080/ws?token={self.client.session.session_token}") as ws:
                async def receiver():
                    async for msg in ws:
                        await self.receiver_queue.put(msg)

                async def sender():
                    while True:
                        msg = await self.sender_queue.get()
                        await ws.send(msg)

                await asyncio.gather(receiver(), sender())

        self.websocket_task = asyncio.create_task(websocket_handler())
        self.process_messages_task = asyncio.create_task(self.process_received_messages())

    
    async def process_received_messages(self):
        """Continuously process messages from receiver_queue and update the UI"""
        while True:
            try:
                msg = await self.receiver_queue.get()

                # Use current screen
                if hasattr(self.screen, "query_one"):
                    try:
                        output = self.screen.query_one("#chat-window-id", Static)
                        current_content = str(output.content)
                        output.update(f"{current_content}\n{msg}")
                    except Exception:
                      pass

                # self.post_message(NewChatMessage(msg))
            except Exception as e:
                self.log(f"Error processing message: {e}")

    async def on_unmount(self):
        """Clean up background tasks when app closes"""
        self.process_messages_task.cancel()
        self.websocket_task.cancel()
        try:
            await self.process_messages_task
            await self.websocket_task
        except asyncio.CancelledError:
            pass
