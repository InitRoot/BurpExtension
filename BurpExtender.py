from burp import IBurpExtender, IScannerCheck, IScanIssue
from burp import IMessageEditorTab  
from burp import IContextMenuFactory
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, Arrays, List
from javax.swing import JMenuItem
from org.python.core.util import StringUtil
from jarray import array
from burp import IBurpExtender
from burp import IContextMenuFactory
from java.util.regex import Matcher, Pattern
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks      
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
      
        
        #setup the extension
        callbacks.setExtensionName('ExampleExtension')

        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)
        # Setup the tab for the results
        tabs = JTabbedPane()
        linkResults_tab = self.set_linkResults_tab(functionality_name, test_name)
        self._resultsViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Results", linkResults_tab)
        self._splitpane.setRightComponent(tabs)

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        #callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
      
        return

    def getTabCaption(self):
        return 'BurpExtension'
    
    def getUiComponent(self):
        return self._splitpane

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to BurpExtension", actionPerformed=self.scanItem))
        return menu_list

    def scanItem(self, event):      
        # Regex used
      
        
       
        httpTraffic = self.context.getSelectedMessages()

        validTraffic = []
        self.paramlist = []
        hostUrls = []
    
        #Only test JS files.
        for traffic in httpTraffic:
            try:
                url = str(traffic.getUrl())
                if ".js" in url:
                    print 'Valid url: '
                    print url + '\n'
                    hostUrls.append(str(traffic.getUrl()))
                    validTraffic.append(traffic)

            except UnicodeEncodeError:
                continue


            
    def consolidateDuplicateIssues(self, isb, isa):
        if Arrays.equals(isb.getHttpMessages()[0].getResponse(), isa.getHttpMessages()[0].getResponse()):
            return -1
        else:
            return 0

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._url.toString()
        return ""


    def set_linkResults_tab(self, fn, vn):
        resource_text = ""

        for url in resource_urls:
            resource_text = resource_text + str(url) + "\n"

        resource_textarea = JTextArea()
        resource_textarea.setLineWrap(True)
        resource_textarea.setWrapStyleWord(True)
        resource_textarea.setText(resource_text)
        resources_panel = JScrollPane(resource_textarea)

        return resources_panel

#
# extend JTable to handle cell selection
#
    
class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return
    
    
