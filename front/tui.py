import asyncio

from textual.app import App
from textual.widgets import Static, Label, Button, Input, Footer
from client.api import Client


class TextualUI(App):
    BINDINGS = [
        ("t", "toggle_background", "toggle"),
        ("l", "lol", "oweir")
    ]

    bg_toggled = False

    def __init__(self, client: Client):
        super().__init__()
        self.client = client
        self.sender_queue = asyncio.Queue()
        self.receiver_queue = asyncio.Queue()

    def compose(self):
        self.static = Static(f"Your session token: [bold red]{self.client.session.session_token}[/bold red]", id="output")
        yield self.static

        self.message_input = Input(placeholder="...")
        yield self.message_input


        # self.label = Label("I am [bold yellow]a yellow[/bold yellow] [yellow]label[/yellow]")
        # yield self.label

        # yield Button("click")
        # yield Button("primary", variant="primary")
        # yield Button.success("success")
        # yield Button.warning("warning")
        # yield Button.error("erro")

        # yield Input(placeholder="your input")
        # yield Input(placeholder="your password", password=True)
        # yield Input(placeholder="your number", type="number", tooltip="digits only, eblan")

        yield Footer()

    def on_mount(self):
        # self.static.styles.background = "blue"
        self.static.styles.border = ("solid", "white")
        self.static.styles.text_align = "center"
        self.static.styles.padding = 4, 11
        self.static.styles.margin = 4, 9

        # Start background task to process received messages
        self.process_messages_task = asyncio.create_task(self.process_received_messages())

    async def process_received_messages(self):
        """Continuously process messages from receiver_queue and update the UI"""
        while True:
            try:
                # Get message from the receiver queue
                msg = await self.receiver_queue.get()

                # Update the static output element
                output = self.query_one("#output", Static)
                current_content = str(output.content)
                output.update(f"{current_content}\n{msg}")

            except Exception as e:
                # Handle any errors gracefully
                self.log(f"Error processing message: {e}")

    def action_toggle_background(self):
        self.bg_toggled = not self.bg_toggled
        if self.bg_toggled:
            self.static.styles.background = "red"
        else:
            self.static.styles.background = "blue"

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        user_text = event.value
        await self.sender_queue.put(user_text)
        # output = self.query_one("#output", Static)
        # current_content = output.content
        # output.update(str(current_content) + f"\n- {user_text}")
        self.message_input.clear()

    async def on_unmount(self):
        """Clean up background task when app closes"""
        if hasattr(self, 'process_messages_task'):
            self.process_messages_task.cancel()
            try:
                await self.process_messages_task
            except asyncio.CancelledError:
                pass
