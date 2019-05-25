#
# 
#
# Copyright (c) 2019 Frans Hendrik Botes.
#
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

      
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        #callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

           
        return


    def createMenuItems(self, invocation):
        self.context = invocation
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Send to Tab", actionPerformed=self.scanItem))
        return menu_list

    def scanItem(self, event):      
        # Regex used
    
        httpTraffic = self.context.getSelectedMessages()

        validTraffic = []
        self.paramlist = []
        hostUrls = []
    
        #Only test JS files and build valid array list.
        for traffic in httpTraffic:
            try:
                url = str(traffic.getUrl())
                if ".js" in url:
                    print 'Valid url: '
                    print url + '\n'
                    response = bytesToString(traffic.getResponse())
                    p = Pattern.compile('.**', Pattern.DOTALL)
                    m = p.matcher(response)
                    # Check match for html pages only
                    # XXX: Java string are automatically boxed into python unicode objects,
                    #      therefore is not possible to use the contains method anymore.
                    #      In order to check if a substring is present in a string, we need
                    #      to use the in operator.
                    if "<js" in response and not m.matches():
                        # The page does NOT contain any SRI attribute
                        issues = ArrayList()
                        issues.add(BLF(traffic))
                        return issues

            
            except UnicodeEncodeError:
                continue


            
    def consolidateDuplicateIssues(self, isb, isa):
        if Arrays.equals(isb.getHttpMessages()[0].getResponse(), isa.getHttpMessages()[0].getResponse()):
            return -1
        else:
            return 0



class BLF(IScanIssue):
    def __init__(self, reqres):
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Blank"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("Some message about background for the issue....")

    def getRemediationBackground(self):
        return "this is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burp Scanner has not identified something in the following page: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        # XXX: Jython arrays are automatically boxed in Java arrays when the
        #      function returns
        rra = [self.reqres]
        return rra

    def getHttpService(self):
        return self.reqres.getHttpService()
  
    
