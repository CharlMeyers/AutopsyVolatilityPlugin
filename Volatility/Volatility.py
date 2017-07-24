from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdaptor
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel

class IngestModuleFactory(IngestModuleFactoryAdaptor):
    def __init__(self):
        self.settings = None
        self.moduleName = "Volatility Processor"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Run Volatility agains a Memory Image"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return None

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        self.settings settings

        return SettingsPanel(self.settings)

    def isDataSourceIngestModule(self):
        True

    def createDataSourceIngestModule(self, ingestOptions):
        return None

class SettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self,settings):
        self.local_settings = settings
