import asyncio
import websockets
import json
import httpx
from httpx import HTTPStatusError

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
        # TODO:  must be conversation_id not uid
        self.uid = uid

    async def on_mount(self):
        headers = {
            "Authorization": f"Bearer {self.client.session.session_token}"
        }
        async with httpx.AsyncClient(base_url=self.client.base_url, headers=headers) as aclient:
            res = await aclient.get("/api/v1/conversations/1/messages")
            if res.status_code != 200:
                raise Exception(f"AsyncClient: error fetching messages. Return code: {res.status_code}")
            self.chat_history = json.loads(res.text)

            # Update the UI after fetching data
            self.query_one("#chat-history-display", Static).update(f"self.chat_history: {self.chat_history['messages']}")
            container = self.query_one("#chat-history-container", VerticalScroll)
            count = 1
            for message in self.chat_history['messages']:
                if count % 2 == 1:
                    await container.mount(Static(message['body'], classes="message message-own"))
                else:
                    await container.mount(Static(message['body'], classes="message message-other"))
                count += 1
            container.scroll_end(animate=False)
                # if message['sender_uid'] == self.client.uid:
                #     await container.mount(Static(str(message), classes="message message-other"))
                # else:
                #     await container.mount(Static(str(message), classes="message message-other"))


    def compose(self):
        yield Static(f"You are talking with {self.uid}")
        with VerticalScroll(id="chat-history-container"):
            pass
        self.message_input = Input(placeholder="Message...")
        yield self.message_input

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        user_text = event.value
        if not event.value:
            return

        payload = {
            "action": "send_message",
            "conversation_id": 1, # TODO
            "body": user_text
        }
        await self.sender_queue.put(json.dumps(payload))
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
            # TODO: store conversation_id in id=
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
                # TODO; conversation_id not uid
                nickname_widget = current.query_one(".nickname", Static)
                uid = str(nickname_widget.content)
                self.push_screen(ChatScreen(self.client, self.sender_queue, uid)) # conversation_id
                break
            current = current.parent

    async def on_mount(self):
        async def websocket_handler():
            async with websockets.connect(f"ws://localhost:8080/api/v1/conversations/ws?token={self.client.session.session_token}") as ws:
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
                        container = self.screen.query_one("#chat-history-container", VerticalScroll)
                        await container.mount(Static(msg, classes="message message-own"))
                        container.scroll_end(animate=False)
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
