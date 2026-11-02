"""NumberedCanvas implementation for two-pass running headers and footers."""

from typing import Any

from reportlab.lib import colors
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas that calculates total pages and draws running headers and footers."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, total_pages: int) -> None:
        # Page 1 is cover page; suppress header and footer
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#4A5568"))

        # Running Header
        header_text = "Cipher-Lens Assessment Report — STRICTLY CONFIDENTIAL"
        self.drawString(54, 750, header_text)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 744, 558, 744)

        # Running Footer
        self.line(54, 45, 558, 45)
        footer_left = "Authorized Lab Security Assessment"
        footer_right = f"Page {self._pageNumber} of {total_pages}"
        self.drawString(54, 34, footer_left)
        self.drawRightString(558, 34, footer_right)

        self.restoreState()
