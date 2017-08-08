import inspect
import os

from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JButton
from javax.swing import JFileChooser
from javax.swing import JComboBox
from javax.swing.filechooser import FileNameExtensionFilter

from java.util.logging import Level
from java.sql import DriverManager, SQLException
from java.lang import Class

from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.casemodule import Case

class VolatilityIngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    moduleName = "Volatility Processor"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Run Volatility against a Memory Image"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return VolatilityIngestModuleSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, VolatilityIngestModuleSettings):
            raise IllegalArgumentException("Settings expected to be instnce of SampleIngestModuleSettings")
        self.settings = settings

        return VolatilityIngestModuleUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return VolatilityIngestModule(self.settings)


class VolatilityIngestModuleUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self, settings):
        head, tail = os.path.split(os.path.abspath(__file__))
        self.absolutePath = head
        self.database = head + "\\VolatilitySettings.db"
        self.localSettings = settings
        self.initLayout()

    def checkDatabase(self):
        runInsertStatements = False
        if not os.path.isfile(self.database):
            runInsertStatements = True

        connection = None
        statement= None

        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            connection = DriverManager.getConnection("jdbc:sqlite:" + self.database)
            if runInsertStatements:
                with open(self.absolutePath + "\\InsertStatements.sql", "r") as file:
                    count = 0
                    for query in file:
                        # Exclude any lines that are empty or contain comment
                        if query != "" and "--" not in query:
                            count += 1
                            try:
                                preparedStatement = connection.prepareStatement(query)
                                preparedStatement.executeUpdate()
                            except SQLException as ex:
                                self.messageLabel.setText("Error at: " + query + "<br />" + ex.message)
                    self.messageLabel.setText("Database created successfully")

            try:
                statement = connection.createStatement()
                query = 'SELECT name, value FROM settings'
                results = statement.executeQuery(query)
                while results.next():
                    if results.getString("name") == "VolatilityExecutableDirectory":
                        self.volatilityDirTextField.setText(results.getString("value"))
                        self.localSettings.setVolatilityDir(results.getString("value"))
                    if results.getString("name") == "VolatilityVersion":
                        self.versionComboBox.setSelectedItem(results.getString("value"))
                    if results.getString("name") == "VolatilityProfile":
                        self.profileComboBox.setSelectedItem(results.getString("value"))
                self.messageLabel.setText("Saved settings loaded successfully")
            except SQLException as ex:
                self.messageLabel.setText("Error reading settings database: " + ex.message)
            finally:
                if statement:
                    statement.close()
        except SQLException as ex:
            self.messageLabel.setText("Error opening settings DB: " + ex.message)
        finally:
            if connection:
                connection.close()

    def findDir(self, event):
        fileChooser = JFileChooser()
        fileExtentionFilter = FileNameExtensionFilter("Executable Files (*.exe)", ["exe"])
        fileChooser.addChoosableFileFilter(fileExtentionFilter)

        result = fileChooser.showDialog(self.mainPanel, "Select File")

        if result == JFileChooser.APPROVE_OPTION:
            file = fileChooser.getSelectedFile()
            canonicalPath = file.getCanonicalPath()

            self.localSettings.setVolatilityDir(canonicalPath)
            self.volatilityDirTextField.setText(canonicalPath)

    def saveSettings(self, event):
        connection = None
        statement = None

        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            connection = DriverManager.getConnection("jdbc:sqlite:" + self.database)

            try:
                statement = connection.createStatement()
                query = 'SELECT count(*) as RowCount FROM settings'
                results = statement.executeQuery(query)
                settingsCount = int(results.getString("RowCount"))

                if settingsCount > 3:
                    directoryStatement = connection.prepareStatement(
                        "UPDATE settings SET value = ? WHERE name = 'VolatilityExecutableDirectory';"
                    )
                    versionStatement = connection.prepareStatement(
                        "UPDATE settings SET value = ? WHERE name = 'VolatilityVersion';"
                    )
                    profileStatement = connection.prepareStatement(
                        "UPDATE settings SET value = ? WHERE name = 'VolatilityProfile';"
                    )
                else:
                    directoryStatement = connection.prepareStatement(
                        "INSERT INTO settings (name, value) VALUES ('VolatilityExecutableDirectory', ?);")
                    versionStatement = connection.prepareStatement(
                        "INSERT INTO settings (name, value) VALUES ('VolatilityVersion', ?);")
                    profileStatement = connection.prepareStatement(
                        "INSERT INTO settings (name, value) VALUES ('VolatilityProfile', ?);"
                    )

                directoryStatement.setString(1, self.volatilityDirTextField.getText())
                versionStatement.setString(1, self.versionComboBox.getSelectedItem())
                profileStatement.setString(1, self.profileComboBox.getSelectedItem())

                directoryStatement.executeUpdate()
                versionStatement.executeUpdate()
                profileStatement.executeUpdate()
                self.messageLabel.setText("Settings saved successfully")
                self.localSettings.setVolatilityDir(self.volatilityDirTextField.getText())
            except SQLException as ex:
                self.messageLabel.setText("Error reading settings database: " + ex.message)
        except SQLException as ex:
            self.messageLabel.setText("Error opening settings DB: " + ex.message)
        finally:
            if statement:
                statement.close()

            if connection:
                connection.close()

    def getProfiles(self):
        connection = None
        statement = None

        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            connection = DriverManager.getConnection("jdbc:sqlite:" + self.database)

            version = self.versionComboBox.getSelectedItem()
            statement = connection.createStatement()
            query = "SELECT name FROM profiles WHERE version = '" + version + "';"
            results = statement.executeQuery(query)
            profiles = []
            while results.next():
                profiles.append(results.getString("name"))

            # statement.close()
            # connection.close()
            return profiles
        except SQLException as ex:
            self.messageLabel.setText("Error opening settings DB:\n" + ex.message)
        finally:
            if statement:
                statement.close()
            if connection:
                connection.close()

    def changeVersion(self, event):
        self.localSettings.setVersion(event.item)
        profileList = self.getProfiles()
        self.profileComboBox.removeAllItems()
        for profile in profileList:
            self.profileComboBox.addItem(profile)

    def changeProfile(self, event):
        self.localSettings.setProfile(event.item)

    def getSettings(self):
        return self.localSettings

    def initLayout(self):
        self.mainPanel = JPanel()

        self.gridBagPanel = GridBagLayout()
        self.gridBagConstraints = GridBagConstraints()
        self.mainPanel.setLayout(self.gridBagPanel)

        # Volatility Executable Path
        self.dirLabel = JLabel("Volatility Executable Directory")
        self.dirLabel.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 1
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 1
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

        self.findVolatilityPathButton = JButton("Find Dir", actionPerformed=self.findDir)
        self.findVolatilityPathButton.setEnabled(True)
        self.gridBagConstraints.gridx = 7
        self.gridBagConstraints.gridy = 3
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.findVolatilityPathButton, self.gridBagConstraints)
        self.mainPanel.add(self.findVolatilityPathButton)

        self.Blank3 = JLabel(" ")
        self.Blank3.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 9
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank3, self.gridBagConstraints)
        self.mainPanel.add(self.Blank3)

        # Version selector
        self.versionLabel = JLabel("Version:")
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 11
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.versionLabel, self.gridBagConstraints)
        self.mainPanel.add(self.versionLabel)

        self.versionList = ("2.5", "2.6")
        self.versionComboBox = JComboBox(self.versionList)
        self.versionComboBox.itemStateChanged = self.changeVersion
        self.gridBagConstraints.gridx = 7
        self.gridBagConstraints.gridy = 11
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.versionComboBox, self.gridBagConstraints)
        self.mainPanel.add(self.versionComboBox)

        self.Blank4 = JLabel(" ")
        self.Blank4.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 13
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank4, self.gridBagConstraints)
        self.mainPanel.add(self.Blank4)

        # Profile selector
        self.profileLabel = JLabel("Profile:")
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 19
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.profileLabel, self.gridBagConstraints)
        self.mainPanel.add(self.profileLabel)

        self.profileList = self.getProfiles()
        self.profileComboBox = JComboBox(self.profileList)
        self.profileComboBox.itemStateChanged = self.changeProfile
        self.gridBagConstraints.gridx = 7
        self.gridBagConstraints.gridy = 19
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 1
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.profileComboBox, self.gridBagConstraints)
        self.mainPanel.add(self.profileComboBox)

        self.Blank5 = JLabel(" ")
        self.Blank5.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 13
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank5, self.gridBagConstraints)
        self.mainPanel.add(self.Blank5)

        self.Blank2 = JLabel(" ")
        self.Blank2.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 22
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank2, self.gridBagConstraints)
        self.mainPanel.add(self.Blank2)

        # Save button
        self.saveButton = JButton("Save Settings", actionPerformed=self.saveSettings)
        self.saveButton.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 24
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.saveButton, self.gridBagConstraints)
        self.mainPanel.add(self.saveButton)

        self.Blank6 = JLabel(" ")
        self.Blank6.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 26
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank6, self.gridBagConstraints)
        self.mainPanel.add(self.Blank6)

        # Message
        self.Label3 = JLabel("Message:")
        self.Label3.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 27
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Label3, self.gridBagConstraints)
        self.mainPanel.add(self.Label3)

        self.messageLabel = JLabel("")
        self.messageLabel.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 31
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 2
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.messageLabel, self.gridBagConstraints)
        self.mainPanel.add(self.messageLabel)

        self.checkDatabase()

        self.add(self.mainPanel)


class VolatilityIngestModule(DataSourceIngestModule):
    def __init__(self, settings):
        self.context = None
        self.localSettings = settings
        self.databaseFile = ""
        self.isAutodetect = False
        self.logger = Logger.getLogger(VolatilityIngestModuleFactory.moduleName)
        # self.setupLogger()

    # def setupLogger(self):
    #     self.logger.setLogDirectory("ModuleLogs")

    def log(self, level, message):
        self.logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], message)

    def startUp(self, context):
        self.context = context

        self.log(Level.INFO, "Volatility Module Loaded")

        self.VolatilityDir = self.localSettings.getVolatilityDir()
        self.Profile = self.localSettings.getProfile()

        if self.Profile == 'Autodetect':
            self.isAutodetect = True
        else:
            self.isAutodetect = False

        message = "<ul>" + \
            "<li>Volatility executable at: " + self.VolatilityDir + "</li>" + \
            "<li>Selected profile: " + self.Profile + "</li>" + "</ul>"

        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                              "Volatiity Settings Loaded", message)
        IngestServices.getInstance().postMessage(inbox)

        if not os.path.exists(self.VolatilityDir):
            raise IngestModuleException("Volatility executable does not exist")

    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Volatiity Process Started")
        IngestServices.getInstance().postMessage(inbox)

        case = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/")

        message = "<p>File names to process:</p> <ul>"
        for file in files:
            message += "<li>" + str(file) + "</li>"

        message += "</ul>"

        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Volatiity Process Information", message)
        IngestServices.getInstance().postMessage(inbox)

        # self.log(Level.INFO, "Datasource filename: ")


class VolatilityIngestModuleSettings(IngestModuleIngestJobSettings):
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
