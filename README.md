Surfstation
===========


Description
-----------
A client and server solution, *Surfstation* aims to provide a simple way for
youth hostels and other institutions with surfstations and/or captive portals
to restrict, monitor and bill their users.


Client
------
Contained in `Client\Client.csproj`, the client can run on any OS that supports
.NET or Mono, although only Windows XP, 7 and Ubuntu 12.04 LTS were tested.


### Configuration

The `SurfstationClient.exe.config` is used to specify:

* The server connection method (for more information have a look at the
  `<system.serviceModel>` documentation).
* `Target`: the user-friendly server name used in logon dialogs.
* `Interval`: The interval at which the client sends a screenshot to the server
  and checks if the user is still allowed to use the station.
* `Quality`: The image compression quality in percent.


### Deployment

* Windows:
  The program should be registered as a replacement for `userinit.exe` which is
  done by placing the executable and the configuration file into
  `%SystemRoot%\system32` and setting the registry key
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
  to `SurfstationClient.exe`. Furthermore, a software restriction policy should
  be defined to restrict the user from running anything that isn't preinstalled
  or allows him or her to adjust a process's access control list, since that is
  how the *Surfstation* client prevents the user from killing the process.

* Ubuntu:
  The `ubuntu.sh` helps speed up the installation quite significantly. Simply
  adjust the first couple of lines to your needs and copy it together with
  `SurfstationClient.exe` and the configuration file onto a USB stick and run
  it on the clients.

  The script will
  - install the required packages
  - enable automatic updates for all repos
  - disable the network manager (please configure `/etc/network/interfaces`
    prior to executing the script)
  - install the program and register it with `lightdm`
  - setup print-to-mail and
  - protect GRUB.

  After that a user can select the guest session, gets prompted for the
  server credentials, and is presented with the Gnome classic shell. (Other
  shells can be selected in the greeter as well.)


Server
------
There are three parts to `Server\Server.csproj` that are explained in the next
couple of lines.

* RADIUS:
  A simple server that accepts a `AccessRequest` containing `User-Name` and
  `User-Password` and returns either `AccessReject` or `AccessAccept` with an
  optional `Session-Timeout`. The listening port and address as well as the
  shared secret are configured through `SurfstationServer.exe.config`.

* WCF service:
  The actual server module for surfstations. Configured in the aforementioned
  file, you can also adjust the size and format of the screenshots before they
  are stored in the third and last module.

* DB connector:
  Any database that can be accessed by the `System.Data.OleDb` provider is
  supported.
  The screenshots are stored as OLE object which can be displayed by *Access*.

  Seven commands have to be defined:
  * `CommandInitialLogin`:
    Verifies that a user can logon and returns the user id, a transparent state
    object that will be passed to all consecutive commands and the amount of
    time in seconds before the user gets logged off. If the timeout is zero, no
    `Session-Timeout` will be set in the RADIUS response packet. The input
    parameters consist of the user name and the plain-text password.
  * `CommandCreateSession`:
    Informs the database that a user session has been created. The command will
    be offered the user id, the transparent state, the amount of seconds that
    the session will last (in case it's a session that cannot be terminated)
    and the name of the client, which can either be a computer name or hardware
    address. The command must then insert a new row into the session table.
  * `CommandGetIdentity`:
    Gets the id of the last created database entry. So far it is only used with
    `CommandCreateSession`.
  * `CommandVerifyLogin`:
    This command is given the user id and transparent state and must return a
    boolean indicating whether the user is still allowed to use the station.
  * `CommandUpdateDuration`:
    After being given the new amount of seconds and the session id, the command
    must update the database session table accordingly.
  * `CommandUpdateScreenshot`:
    This command takes the binary screenshot OLE object and the session id to
    store the screenshot within the database. Unlike other functions, this
    command may fail without terminating the user session on the surfstation.
  * `CommandCleanupScreenshots`:
    This command will be called periodically (the interval can be configured)
    to clean up unused screenshots. The only parameter is the interval itself.

The server binary `SurfstationServer.exe` is a Windows service and can be
installed and configured with `sc`. Make sure that you configure the service to
restart upon failure and that you choose a proper transport or message security
in your WCF configuration.
