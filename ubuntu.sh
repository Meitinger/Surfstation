#!/bin/sh
# Copyright (C) 2013, Manuel Meitinger
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.


########################
# script configuration #
########################

# print-to-mail settings
MAIL_SENDER="no-reply@example.com"
MAIL_RECIPIENT="frontdesk@example.com"
MAIL_SUBJECT="[surfstation] Printout from \$(hostname)"
MAIL_BODY="Please print the attached PDF.\n\nBest regards,\nSurfstation \$(hostname)"
MAIL_SMARTHOST="smarthost.example.com"

# GRUB security settings (use grub-mkpasswd-pbkdf2 to generate the password)
GRUB_USERNAME="root"
GRUB_PASSWORD="grub.pbkdf2.sha512.10000.biglongstring"

# the directory where SurfstationClient.exe and SurfstationClient.exe.config can be found
SOURCE_PATH=.


#################################
# install all required packages #
#################################

# uncomment the partner repository
sed -r 's/# deb(-src)? http:\/\/archive\.canonical\.com\/ubuntu precise partner/deb\1 http:\/\/archive\.canonical\.com\/ubuntu precise partner/' -i /etc/apt/sources.list

# update the headers
apt-get update

# install the classic Gnome Shell, Skype, Mono including all required bindings, and the print-to-mail packages
apt-get install gnome-shell skype mono-complete gnome-sharp2 gtk-sharp2 cups-pdf heirloom-mailx


###############################
# configure automatic updates #
###############################

# enable daily unattended updates and weekly auto-cleans
cat << 'EOC' > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOC

# install all updates and make sure that a quick shutdown is always possible
cat << 'EOC' > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
	"${distro_id}:${distro_codename}-updates";
	"${distro_id}:${distro_codename}-proposed";
	"${distro_id}:${distro_codename}-backports";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
EOC


###############################
# disable the network manager #
###############################

# use /etc/network/interfaces instead
echo "manual" > /etc/init/network-manager.override
stop network-manager


###################################
# set the proper lightdm defaults #
###################################

# use Gnome Shell
/usr/lib/lightdm/lightdm-set-defaults --session gnome-classic

# allow guest sessions
/usr/lib/lightdm/lightdm-set-defaults --allow-guest true


###########################
# install the application #
###########################

# copy the binary and config file
install "$SOURCE_PATH/SurfstationClient.exe" /usr/lib/lightdm/lightdm/SurfstationClient.exe
cp "$SOURCE_PATH/SurfstationClient.exe.config" /usr/lib/lightdm/lightdm/SurfstationClient.exe.config

# create a new guest session wrapper that calls the application
cat << 'EOC' > /usr/lib/lightdm/lightdm/lightdm-guest-session-wrapper
#!/bin/sh
/usr/bin/mono /usr/lib/lightdm/lightdm/SurfstationClient.exe "$@"
EOC
chmod +x /usr/lib/lightdm/lightdm/lightdm-guest-session-wrapper


#############################################
# configure the print-to-mail functionality #
#############################################

# create the post-processing script
mkdir -p /usr/lib/cups-pdf
cat << EOC > /usr/lib/cups-pdf/postprocessing
#!/bin/sh
echo "$MAIL_BODY" | /usr/bin/mailx -s "$MAIL_SUBJECT" -a "\$1" -S smtp="$MAIL_SMARTHOST" -r "$MAIL_SENDER" "$MAIL_RECIPIENT"
EOC
chmod +x /usr/lib/cups-pdf/postprocessing

# register the script with cups-pdf
sed -r 's/^#PostProcessing/PostProcessing \/usr\/lib\/cups-pdf\/postprocessing/' -i /etc/cups/cups-pdf.conf
restart cups

# exclude the script from any AppArmor restrictions on cups-pdf
if ! grep -q '/usr/lib/cups-pdf/postprocessing' /etc/apparmor.d/usr.sbin.cupsd; then
sed -r '/\/etc\/cups\/cups-pdf.conf r,/a\  \/usr\/lib\/cups-pdf\/postprocessing Ux,' -i /etc/apparmor.d/usr.sbin.cupsd
fi
/etc/init.d/apparmor reload

# pre-create the PDF folder (otherwise the first print job fails)
mkdir -p /etc/skel/PDF


##################################
# protect GRUB2 from wrong-doers #
##################################

# append the superuser declaration to the grub header file
if ! grep -q 'set superusers' /etc/grub.d/00_header; then
cat << EOC >> /etc/grub.d/00_header

# Secure GRUB
cat << EOF
set superusers="$GRUB_USERNAME"
password_pbkdf2 $GRUB_USERNAME $GRUB_PASSWORD 
export superusers
EOF

EOC
update-grub
fi
