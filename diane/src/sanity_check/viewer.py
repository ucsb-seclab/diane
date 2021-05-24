from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QScrollArea, QLabel
from PyQt5.QtCore import Qt
from pysoot.sootir.soot_method import SootMethod
import json

# Ref: https://stackoverflow.com/questions/57518567/why-isnt-ipython-rendering-qt-windows-correctly-from-interactive-console

class Viewer(QWidget):
    def __init__(self, text):
        super().__init__()
        self.title = "Soot Viewer"
        self.top = 200
        self.left = 500
        self.width = 600
        self.height = 300
        self.setWindowTitle(self.title)
        self.resize(400, 200)
        self.move(300, 300)
        self.setGeometry(self.left, self.top, self.width, self.height)
        scroll = QScrollArea()
        label = QLabel(self)
        label.setText(text)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        scroll.setWidget(label)
        scroll.setWidgetResizable(True)
        layout = QVBoxLayout(self)
        layout.addWidget(scroll)
        self.setLayout(layout)
        self.show()

# Qt lives in an event loop that allows you to execute
# tasks such as rendering, listen to OS events, etc.
# But with time.sleep(), you block it causing the GUI 
# to freeze. Returning the `viewer` object helps ipython
# to maintain a reference which, in turn, prevents the
# GC from garbage collecting it; hereby killing the UI
def view(object):
    if isinstance(object, SootMethod):
        text = str(object)
    else:
        text = object
    viewer = Viewer(text)
    return viewer 

def pretty_print_result(result_dict):
    print(json.dumps(result_dict, indent=4))

# Start IPython --gui=qt5, or type %gui qt5
# after you've started IPython to use modules
# using Qt backend interactively. IPython, in
# this case, provides its own event loop instead
# of the one started by QApplication.exec()
if __name__ == '__main__':
    #if QApplication.instance() is None:
    app = QApplication([])
    Viewer('DUMMY TEXT')
    app.exec_()
