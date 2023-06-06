#############################################################
# 
#                                                             HP Confidential
#
#            This script is classified as HP Confidential. This script is not to be shared with customers 
#            or any HP personnel other than authorized HP Converged Systems Engineering Teams 
#            and Deployment Engineers performing solution configuration. The purpose of this script is to
#            configure the solution with the assumption that no configuration is in effect at the time of
#            script execution.
#             
#             THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
#             OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
#             FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
#             THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
#             LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
#             OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
#             THE SOFTWARE.
#
#             © 2014 Hewlett-Packard Development Company, L.P. 
#
#############################################################

@{
    
    # Script module or binary module file associated with this manifest
    RootModule = 'Common_Powershell.psm1'
    
    # Version number of this module.
    ModuleVersion = '4.10.000'
    
    # ID used to uniquely identify this module
    GUID = ''
    
    # Author of this module
    Author = 'Hewlett-Packard'
    
    # Company or vendor of this module
    CompanyName = 'Hewlett-Packard'
    
    # Copyright statement for this module
    Copyright = '(C) Copyright 2014 Hewlett-Packard Development Company, L.P.'
    
    # Description of the functionality provided by this module
    Description = 'HPE Build'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '3.0'
    
    # Name of the Windows PowerShell host required by this module
    PowerShellHostName = ''
    
    # Minimum version of the Windows PowerShell host required by this module
    PowerShellHostVersion = ''
    
    # Minimum version of the .NET Framework required by this module
    DotNetFrameworkVersion = '4.0'
    
    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion = '4.0'
    
    # Processor architecture (None, X86, Amd64) required by this module
    #ProcessorArchitecture = ''
    
    # Modules that must be imported into the global environment prior to importing this module
    #RequiredModules = @(HPOneView.120, Logger)
    
    # Assemblies that must be loaded prior to importing this module
    #RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    #ScriptsToProcess = @()
    
    # Type files (.ps1xml) to be loaded when importing this module
    #TypesToProcess = @()
    
    ###
	# Format files (.ps1xml) to be loaded when importing this module
    #FormatsToProcess = @('HPOneView.120.format.ps1xml')
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    #NestedModules = @()
    
    # Functions to export from this module
    #FunctionsToExport = '*'
    
    # Cmdlets to export from this module
    #CmdletsToExport = '*'
    
    # Variables to export from this module
    #VariablesToExport = '*'
    
    # Aliases to export from this module
    #AliasesToExport = '*'
    
    # Commands to export from this module as Workflows
    #ExportAsWorkflow = @()
    
    # List of all modules packaged with this module
    ModuleList = @('Common_Powershell.psm1')
    
    # List of all files packaged with this module
    FileList = @('Common_Powershell.psd1','Common_Powershell.psm1')
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    #PrivateData = ''
    
    # HelpInfo URI of this module
    HelpInfoURI = 'http://www.hp.com/go/OneViewPowershell/updatehelp'
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    #DefaultCommandPrefix = ''

}