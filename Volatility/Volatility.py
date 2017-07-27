from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JButton

from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule


class IngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None
        self.moduleName = "Volatility Processor"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Run Volatility against a Memory Image"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return IngestModuleSettings

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, IngestModuleSettings):
            raise IllegalArgumentException("Settings expected to be instnce of SampleIngestModuleSettings")
        self.settings = settings

        return IngestModuleUISettingsPanel(self.settings)

    def isDataSourceIngestModule(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return IngestModule(self.settings)


class IngestModuleUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self, settings):
        self.local_settings = settings
        self.initLayout()

    def initLayout(self):
        self.mainPanel = JPanel()

        self.gridBagPanel = GridBagLayout()
        self.gridBagConstraints = GridBagConstraints()
        self.mainPanel.setLayout(self.gridBagConstraints)

        # Volatility Executable Path
        self.dirLabel = JLabel("Volatility Executable Directory")
        self.dirLabel.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 1
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.dirLabel, self.gridBagConstraints)
        self.mainPanel.add(self.dirLabel)

        self.volatilityDirTextField = JTextField(10)
        self.volatilityDirTextField.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 3
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.volatilityDirTextField, self.gridBagConstraints)
        self.mainPanel.add(self.volatilityDirTextField)

        self.FindVolatilityPathButton = JButton("Find Dir", actionPerformed=self.Find_Dir)
        self.FindVolatilityPathButton.setEnabled(True)
        self.rbgmainPanel.add(self.FindVolatilityPathButton)
        self.gridBagConstraints.gridx = 6
        self.gridBagConstraints.gridy = 3
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.FindVolatilityPathButton, self.gridBagConstraints)
        self.mainPanel.add(self.FindVolatilityPathButton)


class IngestModule(DataSourceIngestModule):
    def __init__(self, settings):
        self.context = None
        self.localSettings = settings
        self.databaseFile = ""
        self.isAutodetect = False
        self.AdditionalParams = ""
        self.PythonProgram = False

    def startUp(self, context):
        self.context = context

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()

class IngestModuleSettings(IngestModuleIngestJobSettings):
    def __init__(self):
        self.versionUID = 1L
        self.VolatilityDir = ""
        self.Version = "2.5"
        self.Profile = "Autodetect"

    # Getters and setters
    def getVersionUID(self):
        return self.versionUID

    def getVolatilityDir(self):
        return self.VolatilityDir

    def getVersion(self):
        return self.Version

    def getProfile(self):
        return self.Profile

    def setVolatilityDir(self, dir):
        self.VolatilityDir = dir

    def setVersion(self, version):
        self.Version = version

    def setProfile(self, profile):
        self.Profile = profile
