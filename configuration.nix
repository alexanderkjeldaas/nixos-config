# Edit this configuration file to define what should be installed on
# the system.  Help is available in the configuration.nix(5) man page
# or the NixOS manual available on virtual console 8 (Alt+F8).

{ config, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

#  boot.zfs.useGit = true;
  boot.initrd.kernelModules =
    [ # Specify all kernel modules that are necessary for mounting the root
      # filesystem.
      "xfs" "ata_piix"
      "crc32c" # for btrfs
      "libcrc32c" # for btrfs
      "zlib_deflate" # for btrfs
      "xor" # for btrfs
      "raid6_pq" # for btrfs
      "ext4"
      "ext3"
      "btrfs"
      "tpm_tis"
      "tpm"
      "tpm_bios"
      "hw_random"
#      "intel-rng"
    ];
    
  # Use the GRUB 2 boot loader.
  boot.loader.grub.enable = true;
  boot.loader.grub.version = 2;

  # Define on which hard drive you want to install Grub.
  boot.loader.grub.device = "/dev/sda"; #"nodev"; #"/dev/sda";
  boot.loader.grub.trustedBoot.enable = true;
  #virtualisation.memorySize = "2G";
  #virtualisation.graphics = false;

  boot.initrd.luks.devices = [
      {
        name = "luksroot";
	device = "/dev/sda1";
 	preLVM = true;
	tpm.autoInstall = true;
        tpm.autoInstallFilesystem = "btrfs";
	tpm.storage.device = "/dev/sda2";
	tpm.storage.path = "/tpm-luks-sealed-key";
      }
  ];
  boot.initrd.luks.tpmSupport = true;

  users.mutableUsers = false;

  networking.hostName = "fp-nl-2"; # Define your hostname.
  # networking.wireless.enable = true;  # Enables Wireless.
  networking.defaultGateway = "79.142.64.1";
  networking.interfaces = {
      eno1 = {
  	ipAddress = "79.142.64.225";
	prefixLength = 24;
      };
  };
  networking.nameservers = [ "8.8.8.8" ];
  networking.useDHCP = false;
  networking.firewall.enable = true;
  networking.firewall.connectionTrackingModules = [];
  networking.firewall.allowedTCPPorts = [ 22 25 80 9000 8081 8082 6927 9176];
  networking.firewall.allowedUDPPorts = [ 6916 ];
  networking.firewall.allowPing = true;

  networking.nat.enable = true;
  networking.nat.internalInterfaces = ["c-+"];
  networking.nat.externalInterface = "eno0";
  networking.defaultMailServer.domain = "privateflows.net";


  # Add filesystem entries for each partition that you want to see
  # mounted at boot time.  This should include at least the root
  # filesystem.

  fileSystems."/".device = "/dev/mapper/nixos--vg-root";
  fileSystems."/boot".device = "/dev/sda2";

  # fileSystems."/data" =     # where you want to mount the device
  #   { device = "/dev/sdb";  # the device
  #     fsType = "ext3";      # the type of the partition
  #     options = "data=journal";
  #   };

  # List swap partitions activated at boot time.
  swapDevices =
    [ { device = "/dev/mapper/nixos--vg-swap_1"; }
    ];

  # Select internationalisation properties.
  # i18n = {
  #   consoleFont = "lat9w-16";
  #   consoleKeyMap = "us";
  #   defaultLocale = "en_US.UTF-8";
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  services.openssh.enable = true;
  services.openssh.passwordAuthentication = false;
  #services.openssh.permitRootLogin = "yes";
  services.tcsd.enable = true;  
  services.openvpn.enable = true;

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable the X11 windowing system.
  # services.xserver.enable = true;
  # services.xserver.layout = "us";
  # services.xserver.xkbOptions = "eurosign:e";

  # Enable the KDE Desktop Environment.
  # services.xserver.displayManager.kdm.enable = true;
  # services.xserver.desktopManager.kde4.enable = true;
  services.sshd.enable = true;
  services.dbus.enable = true;
  services.fail2ban.enable = true;

  # Postfix setup
  services.postfix = {
#    destination = [ "localhost" "trust.is" "formalprivacy.com"
#                    "privateflows.net" ];
    enable = true;
    domain = "privateflows.net";
    hostname = "mail-fp-nl-3.privateflows.net";
    origin = "privateflows.net";
    postmasterAlias = "root";
    rootAlias = "cfl";
    virtualMailboxEnabled = true;
    virtualMailboxDomains = ["privateflows.net"];
    virtualMailboxMaps = [
      "astor@privateflows.net privateflows.net/astor/"
    ];
    extraConfig = ''
      # TLS session reuse cache
      smtpd_tls_session_cache_database = btree:/var/postfix/smtpd_scache
      smtpd_tls_session_cache_timeout = 3600s
      smtpd_tls_mandatory_protocols = !SSLv2
      smtpd_tls_loglevel = 1
      # For all options see ``man 5 postconf``
      # Take care, empty lines will mess up whitespace removal. It would be
      # nice if empty lines would not be considered in minimal leading
      # whitespace analysis, but don't know about further implications. Also
      # take care not to mix tabs and spaces. Should tabs be treated like 8
      # spaces?
      #
      # ATTENTION! Will log passwords
      #debug_peer_level = 4
      #debug_peer_list = tesla.chaoflow.net
      #### inet_interfaces = loopback-only
      #
      # the nixos config option does not allow to specify a port, beware:
      # small 'h' in contrast to the config option with capital 'H'
      #### relayhost = [0x2c.org]:submission
      #relayhost = [127.0.0.1]:1587
      #
      #XXX: needs server certificate checking
      #smtp_enforce_tls = yes
      #
      # postfix generic map example content:
      # user@local.email user@public.email
      # Run ``# postmap hash:/etc/nixos/cfg-private/postfix_generic_map``
      # after changing it.
      #### smtp_generic_maps = hash:/etc/nixos/cfg-private/postfix_generic_map
      #### smtp_sasl_auth_enable = yes
      #### smtp_sasl_mechanism_filter = plain, login
      #
      # username and password for smtp auth, example content:
      # <relayhost> <username>:<password>
      # The <relayhost> is exactly what you specified for relayHost, resp.
      # relayhost.
      #### smtp_sasl_password_maps = hash:/etc/nixos/cfg-private/postfix_passwd
      #### smtp_sasl_security_options = noanonymous
      #### smtp_sasl_tls_security_options = $smtp_sasl_security_options
      #### smtp_use_tls = yes
      disable_vrfy_command = yes
      # SHOW SOFTWARE VERSION OR NOT
      smtpd_banner = $myhostname ESMTP NO UCE
      # No biff notifications
      biff = no
      # Default message size limit is 10MiB, gmail is 20MiB.
      # We use 100MiB
      message_size_limit    =   104857600
      virtual_mailbox_limit = 0
      #
      smtpd_helo_required = yes
      smtpd_helo_restrictions = permit_mynetworks,
#           check_helo_access hash:/usr/local/etc/postfix/helo_access,
           reject_non_fqdn_hostname,
           reject_invalid_hostname,
           permit
    '';
    sslCert = /etc/nixos/certs/mail-fp-nl-3.privateflows.net.cert.combined.pem;
    sslKey = /etc/nixos/certs/mail-fp-nl-3.privateflows.net.ssl.key;
    #sslCACert = /etc/nixos/certs/startcom-ca.pem;
  };

  services.opendkim = {
    enable = true;
    keys."privateflowsNet" = {
      domain = "privateflows.net";
      selector = "mail-fp-nl-3";
      # openssl genrsa -out rsa.private 2048
      # openssl rsa -in rsa.private -out rsa.public -pubout -outform PEM
      keyFile = "/var/lib/opendkim/keys/mail-fp-nl-3.privateflows.net.private.pem";
      key = "privateflowsNet";
    };
    signingTable = [ "*@privateflows.net privateflowsNet" ];
    extraTrustedHosts = [ "*.privateflows.net" ];
  };

  #services.spamassassin.enable = true;

  systemd.services.prserver = {
#    enabled = true;
    description = "Public record server";
    after = [ "network.target" ];
    # We're going to run it on port 8080 in production
    environment = { PORT = "8080"; };
    serviceConfig = {
      # The actual command to run
      ExecStart = "${pkgs.nodejs}/bin/node ${pkgs.prserver}/test-server.js";
      # For security reasons we'll run this process as a special 'nodejs' user
      User = "prserver";
      Restart = "always";
    };
  };


  # TODO: Rebuilding the accountserver without etcd running fails,
  # since the etcd haskell package tests run against a real server.
#   systemd.services.accountserver = {
# #    enabled = true;
#     description = "Public record server";
#     after = [ "network.target" ];
#     serviceConfig = {
#       # The actual command to run
#       ExecStart = "${pkgs.accounts}/bin/accounts";
#       User = "accountserver";
#       Restart = "always";
#     };
#   };

#  security.grsecurity.config.system = "server";
#  security.grsecurity.enable = true;
#  security.grsecurity.testing = true;


  security.initialRootPassword = "$6$6fWLoQOH$D96Pk5rtn6FI6B.GXtdJGU74dSrh7RlfXD7lTL3CokHRQsfu3Ha/ugKCHywjnXP5tqUOhc44PnKM0r95hyfOZ/";

  # And lastly we ensure the user we run our application as is created
  users.extraUsers = {
    astor = { uid = 1000;
              home = "/home/astor";
	      hashedPassword = "$6$rkp0lMJs$g227YxV6nJ0.KntVNllFP8/m1eIvJcd3jnQhy88WLKtMbkWsGtVE0NcXTwZpET6oRpbX.pdW9gg4W7vX6IbUN0";
	      shell = "/run/current-system/sw/bin/bash";
    };
    prserver = { uid = 1001; };
    accountserver = { uid = 1002; };
    adevel = { uid = 1003;
              home = "/home/adevel";
 	      createHome = true;
	      hashedPassword = "$6$rkp0lMJs$g227YxV6nJ0.KntVNllFP8/m1eIvJcd3jnQhy88WLKtMbkWsGtVE0NcXTwZpET6oRpbX.pdW9gg4W7vX6IbUN0";
	      shell = "/run/current-system/sw/bin/bash";
    };
  };
  
	
  sound.enable = false;
  #nix.cores = 8;
  nix.extraOptions          = ''
    gc-keep-outputs = true
    build-cores = 16'';
  nix.useChroot = false;
  nix.binaryCaches = [];

  security.grsecurity = {
    # enable = true;
      testing = true;   # or "stable = true;"
      config = {
        system = "server";     # or "desktop"
        priority = "security";   # or "performance"
        kernelExtraConfig = ''
         GRKERNSEC_RANDSTRUCT n
         GRKERNSEC_HIDESYM n
         PAX_KERNEXEC? n
         PAX_SIZE_OVERFLOW? n
       '';
    };
  };

  nixpkgs.config = {
#    grsecurity = true;
    packageOverrides = pkgs:
       let hp =  pkgs.haskellPackages_ghc783 // {
#         etcd = pkgs.haskellPackages_ghcHEAD.callPackage ./formalprivacy/haskell/etcd-0.1.0.3/nix {};
       };
       in {
       gcc = pkgs.wrapGCC (pkgs.gcc.gcc.override {
         profiledCompiler = false;
       });
#      gcc = pkgs.gcc46_deterministic;
#      binutils = pkgs.binutils_deterministic;
       prserver = pkgs.callPackage ./formalprivacy/nix/pr-server {};
       accounts = hp.callPackage ./formalprivacy/haskell/accounts/nix {};
       haskellPackages = hp;
       linuxPackages = pkgs.linuxPackages_grsec_testing_server;
       linux = pkgs.linux_grsec_testing_server;
#       spl = pkgs.spl_git;
       stdenv = pkgs.stdenv // {
          platform = pkgs.stdenv.platform // {
            kernelExtraConfig = ''
9P_FS n
ACCESSIBILITY y
ADFS_FS n
AFFS_FS n
AFS_FS n
AGP n
AUTOFS4_FS n
AX25 n
BACKLIGHT_GENERIC n
BEFS_FS n
BFS_FS n
BT n
CAN n
CEPH_FS y
# CEPH_FSCACHE y
CEPH_FS_POSIX_ACL y
CIFS n
CODA_FS n
CRAMFS n
# DONGLE n
DRM n
ECRYPT_FS n
EFIVAR_FS n
EFS_FS n
EXOFS_FS n
EXT4_DEBUG n
F2FS_FS n
# FAT_FS n
# FS_MBCACHE n
FS_XIP y
GFS2_FS n
HFSPLUS_FS n
HFS_FS n
HPFS_FS n
INFINIBAND n
INTEL_IOMMU_DEFAULT_ON y
INTEL_TXT y
IRDA n
ISO9660_FS n
# JBD n
# JBD2 n
JFFS2_FS n
JFS_FS n
# JOLIET y
LCD_CLASS_DEVICE n
# LNET n
# LOCKD n
#LOCKD_V4 n
LOGFS n
LUSTRE_FS n
MINIX_FS n
# MKISS n
MSDOS_FS n
NCP_FS n
#NETROM n
NETWORK_FILESYSTEMS y
NFC n
NFSD n
NFS_FS n
NILFS2_FS n
# NLS n
NTFS_FS n
OCFS2_FS n
OMFS_FS n
# ORE n
PAX n
# PAX_RANDKSTACK n
# PAX_RANDUSTACK n
PSTORE n
QNX4FS_FS n
QNX6FS_FS n
RAPIDIO n
REISERFS_FS n
ROMFS_FS n
# ROSE n
# RPCSEC_GSS_KRB5 n
SOUND n
SPEAKUP n
SQUASHFS n
# SUNRPC n
SYSV_FS n
UBIFS_FS n
UDF_FS n
UFS_FS n
# USB_ACM n
USB_PRINTER n
USB_STORAGE n
USB_TMC n
# USB_WDM n
VFAT_FS n
VXFS_FS n
VXFS_FS n
# WIRELESS n
# YAM n
YENTA n
# ZISOFS y
	      '';
         };
       };
    };
    allowUnfree = true;
  };
  
  #environment.noXlibs = true;
  environment.systemPackages = with pkgs; [
   lxc tboot tpm-tools trousers vim tpm-quote-tools openssl
#   rsync # needed for nixos-install
   prserver
   etcd
   mailpile
#   accounts
   ceph
   mosh
   smartmontools
  ];
  services.etcd.enable = true;
  # Future options to disable
  services.httpd.enable = true;
  services.httpd.adminAddr = "ak@formalprivacy.com";
  services.httpd.documentRoot = "/data/webserver/docs";
  services.httpd.extraConfig = ''
    <Directory /data/webserver/docs/static>
      <Files "stage0.js">
        Header set Cache-Control "max-age=2147483647, public"
        Header unset ETag
        FileETag None
        # Header set ExpiresExpires: Fri, 30 Oct 1998 14:19:41 GMT
        # We must have ETag or Last-Modified.  To not have "smart" browsers
        # re-fetching the document, we backdate.
        Header set Last-Modified "Mon, 29 Jun 1998 02:28:12 GMT"
      </Files>
    </Directory>
    '';

  services.postgresql.enable = true;
  services.postgresql.package = pkgs.postgresql93;

  # Future hardening options
  # Disables virtual terminals
  # services.logind.extraConfig = ''
  #  NAutoVTs=0
  #  ReserveVT=0'';
  # systemd.units."getty@tty1".enable = false;
  # systemd.enableEmergencyMode = false;

  # TODO: Remove 
  systemd.services.nix-daemon.environment.TMPDIR = "/boot/tmp";

  # nixos-container for each user
  containers.user = {
    privateNetwork = true;
    #hostAddress = "192.168.102.10";
    #localAddress = "192.168.102.11";
    
    config = { config, pkgs, ... }: { 
      # two additional programs are installed in the environment
      environment.systemPackages = with pkgs; [
        wget
        nmap
        mailpile
      ];
      networking.firewall = {
        enable = true;
        allowedTCPPorts = [ 80 443 ];
      };

      users.extraUsers = {
        user = { uid = 10000; };
      };

      services.httpd = {
        enable = true;
        enableSSL = false;
        adminAddr = "web2@example.org";
        documentRoot = "/webroot";
#        extraModules = [
#          # here we are using php-5.3.28 instead of php-5.4.23
#          { name = "php5"; path = "${pkgs.php53}/modules/libphp5.so"; }
#        ];
      };

      systemd.services.mailpile = {
#       enabled = true;
        description = "Mailpile server";
        after = [ "network.target" ];
        # We're going to run it on port 8080 in production
        # environment = { PORT = "8080"; };
        serviceConfig = {
          # The actual command to run
          ExecStart = "${pkgs.mailpile}/bin/mailpile";
          # For security reasons we'll run this process as a special 'nodejs' user
          User = "user";
          Restart = "always";
        };
      };
    };
  };
}
