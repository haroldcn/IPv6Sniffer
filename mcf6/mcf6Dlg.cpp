// mcf6Dlg.cpp : Implementation file
//

#include "stdafx.h"
#include "mcf6.h"
#include "mcf6Dlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// For Applications "on" CAboutDlg dialog menu items
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter);

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();
    
// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV Support

//Achieve
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// Cmcf6Dlg Dialog




Cmcf6Dlg::Cmcf6Dlg(CWnd* pParent /*=NULL*/)
	: CDialog(Cmcf6Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cmcf6Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_EDIT2, m_editNTcp);
	DDX_Control(pDX, IDC_EDIT3, m_editNUdp);
	DDX_Control(pDX, IDC_EDIT4, m_editNIcmp);
	DDX_Control(pDX, IDC_EDIT5, m_editNIp);
	DDX_Control(pDX, IDC_EDIT6, m_editNArp);
	DDX_Control(pDX, IDC_EDIT7, m_editNHttp);
	DDX_Control(pDX, IDC_EDIT8, m_editNOther);
	DDX_Control(pDX, IDC_EDIT9, m_editNSum);
	DDX_Control(pDX, IDC_BUTTON5, m_buttonSave);
	DDX_Control(pDX, IDC_BUTTON4, m_buttonRead);
	DDX_Control(pDX, IDC_EDIT10, m_editNIpv4);
	DDX_Control(pDX, IDC_EDIT11, m_editIcmpv6);
}

BEGIN_MESSAGE_MAP(Cmcf6Dlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, &Cmcf6Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &Cmcf6Dlg::OnBnClickedButton2)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &Cmcf6Dlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &Cmcf6Dlg::OnNMCustomdrawList1)
	ON_BN_CLICKED(IDC_BUTTON5, &Cmcf6Dlg::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON4, &Cmcf6Dlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// Cmcf6Dlg Message Handler

BOOL Cmcf6Dlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// The "About ..." menu item added to the system menu.

	// IDM_ABOUTBOX Must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

// Set the icon for this dialog. When the application's main window is not a dialog box, the framework will automatically
//  Do this
	SetIcon(m_hIcon, TRUE);			// Large Icons Set
	SetIcon(m_hIcon, FALSE);		// Small Icons Set

	ShowWindow(SW_MINIMIZE);

	// TODO: Add extra initialization code
    m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);

	m_listCtrl.InsertColumn(0,_T("ID"),3,30);                        //1 indicates the right, 2 indicates center, 3 indicates the left
	m_listCtrl.InsertColumn(1,_T("TIME"),3,130);
	m_listCtrl.InsertColumn(2,_T("LENGTH"),3,72);
	m_listCtrl.InsertColumn(3,_T("Source MAC Address"),3,140);
	m_listCtrl.InsertColumn(4,_T("Destination MAC Address"),3,140);
	m_listCtrl.InsertColumn(5,_T("PROTOCOL"),3,70);
	m_listCtrl.InsertColumn(6,_T("Source IP Address"),3,145);
	m_listCtrl.InsertColumn(7,_T("Destination IP Address"),3,145);

	m_comboBox.AddString(_T("Please Select a Network Interface (Required)"));
	m_comboBoxRule.AddString(_T("Please Select Filtering rules (Optional)"));
	
	if(lixsniff_initCap()<0)
		return FALSE;

	/*Initialization interface list*/
	for(dev=alldev;dev;dev=dev->next)
	{
		if(dev->description)
			m_comboBox.AddString(CString(dev->description));  //////////////////////////////Problem 1Character Set
	}   

	/*Initialization Filtering Rule list*/
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));

	m_comboBox.SetCurSel(0);
	m_comboBoxRule.SetCurSel(0);

	m_buttonStop.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(FALSE);

	//m_bitButton.RedrawWindow();

	/////////////////////////////////////////////////////////////////////////////////////////////////listControl Usage Method
	//int nitem = m_listCtrl.InsertItem(0,_T("hello"));
	/*char buf[5];
	itoa(nitem,buf,10);
	MessageBox(CString(buf));*/
	/*m_listCtrl.SetItemText(nitem,1,_T("jak"));
	m_listCtrl.SetItemText(nitem,2,_T("bub"));
	m_listCtrl.SetItemText(nitem,3,_T("coco"));
	m_listCtrl.SetItemText(nitem,4,_T("haha"));*/
	return TRUE;  //Unless you set the focus to a control, otherwise it returns TRUE
}

void Cmcf6Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the following code
// To draw the icon. For MFC applications using the document / view model,
// This is done automatically by the framework.

void Cmcf6Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); //Device context for drawing

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Icon centered in the work area enable rectangles
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		//Draw icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//When the user drags the minimized window system calls this function to obtain the cursor
//Display
HCURSOR Cmcf6Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/////////////////////////////////////////£ÛEvent Function£Ý///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//Start Button
void Cmcf6Dlg::OnBnClickedButton1()
{
	// TODO:In this notification handler code to add controls
	//If you already have the data, and are prompted to save data
	if(this->m_localDataList.IsEmpty() == FALSE)
	{
		if(MessageBox(_T("Confirmed that the data is not saved£¿"),_T("WARNING"),MB_YESNO)==IDNO)
		{
			this->lixsniff_saveFile();
		}
	}

	this->npkt =1;	//Recount
	this->m_localDataList.RemoveAll();//Every time the outset previously stored data to empty out
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket),0,sizeof(struct pktcount));
	this->lixsniff_updateNPacket();

	if(this->lixsniff_startCap()<0)
		return;
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowTextW(_T(""));
	this->m_buttonStart.EnableWindow(FALSE);
	this->m_buttonStop.EnableWindow(TRUE);
	this->m_buttonSave.EnableWindow(FALSE);
}

//End Button
void Cmcf6Dlg::OnBnClickedButton2()
{
	// TODO:In this notification handler code to add controls
	if(NULL == this->m_ThreadHandle )
		return;
	if(TerminateThread(this->m_ThreadHandle,-1)==0)
	{
		MessageBox(_T("Close thread error, please try again later"));
		return;
	}
	this->m_ThreadHandle = NULL;
	this->m_buttonStart.EnableWindow(TRUE);
	this->m_buttonStop.EnableWindow(FALSE);	
	this->m_buttonSave.EnableWindow(TRUE);
}

//List
void Cmcf6Dlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: In this notification handler code to add controls
	int index;
	index = this->m_listCtrl.GetHotItem();

	if(index>this->m_localDataList.GetCount()-1)
		return;

	this->lixsniff_updateEdit(index);
	this->lixsniff_updateTree(index);
	*pResult = 0;
}

//Save Button
void Cmcf6Dlg::OnBnClickedButton5()
{
	// TODO: In this notification handler code to add controls
	if(this->lixsniff_saveFile()<0)
		return;
}

//Read Button
void Cmcf6Dlg::OnBnClickedButton4()
{
	// TODO:In this notification handler code to add controls
	//Before reading ListCtrl empty
	this->m_listCtrl.DeleteAllItems();
	this->npkt =1; //List recount
	this->m_localDataList.RemoveAll();//Every time the outset previously stored data to empty out
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket),0,sizeof(struct pktcount));//Empty all types of packet count

	//Open File Dialog
	 CFileDialog   FileDlg(TRUE ,_T(".lix"),NULL,OFN_HIDEREADONLY   |   OFN_OVERWRITEPROMPT);   
	 FileDlg.m_ofn.lpstrInitialDir=_T("c:\\");   
	 if(FileDlg.DoModal()==IDOK)   
	 {   
		 int ret = this->lixsniff_readFile(FileDlg.GetPathName());
		 if(ret < 0)
				return;		 
	 }
}

//Change ListCtrl Each row colors
void Cmcf6Dlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	//LPNMCUSTOMDRAW pNMCD = reinterpret_cast<LPNMCUSTOMDRAW>(pNMHDR);
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;
	// TODO: In this notification handler code to add controls
	if(CDDS_PREPAINT==pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}else if(CDDS_ITEMPREPAINT ==pNMCD->nmcd.dwDrawStage){
		COLORREF crText;
		char buf[10];
		memset(buf,0,10);
		POSITION pos = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		struct datapkt * local_data = (struct datapkt *)this->m_localDataList.GetAt(pos);
		strcpy(buf,local_data->pktType);

		if(strcmp(buf,"IPV6")==0)
			crText = RGB(111,224,254);
		else if(strcmp(buf,"UDP")==0)
			crText = RGB(194,195,252);				
		else if(strcmp(buf,"TCP")==0)
				crText = RGB(230,230,230);
		else if(strcmp(buf,"ARP")==0)
				crText = RGB(226,238,227);
		else if(strcmp(buf,"ICMP")==0)
				crText = RGB(49,164,238);
		else if(strcmp(buf,"HTTP")==0)
				crText = RGB(238,232,180);
		else if(strcmp(buf,"ICMPv6")==0)
				crText = RGB(189,254,76);

		pNMCD->clrTextBk =crText;
		*pResult = CDRF_DODEFAULT;
	}
}
//////////////////////////////////////////£ÛPerformance Function£Ý///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//WinPcap Initialization
int Cmcf6Dlg::lixsniff_initCap()
{
	devCount = 0;
	if(pcap_findalldevs(&alldev, errbuf) ==-1)
		return -1;
	for(dev=alldev;dev;dev=dev->next)
		devCount++;	
	return 0;
}

//Start Capture
int Cmcf6Dlg::lixsniff_startCap()
{	
	int if_index,filter_index,count;
	u_int netmask;
	struct bpf_program fcode;

	lixsniff_initCap();

	//Access to the interface and filter index
	if_index = this->m_comboBox.GetCurSel();
	filter_index = this->m_comboBoxRule.GetCurSel();

	if(0==if_index || CB_ERR == if_index)
	{
		MessageBox(_T("Please Select a Network Interface"));
		return -1;
	}
	if(CB_ERR == filter_index)
	{
		MessageBox(_T("Filter selection Error"));	
		return -1;
	}

	/*Access to the selected network interface*/
	dev=alldev;
	for(count=0;count<if_index-1;count++)
		dev=dev->next;
    
	if ((adhandle= pcap_open_live(dev->name,	// device name
							 65536,	//Capture packets LENGTH																					
							 1,	// promiscuous mode (non-zero mean is promiscuous mode) 
							 1000,	//read timeout setting
							 errbuf		// error message
							 )) == NULL)
	{
		MessageBox(_T("Unable to open the interface£º"+CString(dev->description)));	
		pcap_freealldevs(alldev);
		return -1;
	}    

	/*Check whether the Ethernet or not*/
	if(pcap_datalink(adhandle)!=DLT_EN10MB)
	{
		MessageBox(_T("This is not suitable for the non-Ethernet network!"));
		pcap_freealldevs(alldev);
		return -1;
	}

	if(dev->addresses!=NULL)	
		netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask=0xffffff; 

	//±àÒë¹ýÂËÆ÷
	if(0==filter_index)
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("Syntax error, Cannot Compile Filters"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}else{
		CString str;
		char *filter;
		int len,x;
		this->m_comboBoxRule.GetLBText(filter_index,str);
		len = str.GetLength()+1;
		filter = (char*)malloc(len);
		for(x=0;x<len;x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("Syntax error, Cannot Compile Filters"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}


	//Set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		MessageBox(_T("Set the Filter Error"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/*Set the packet storage path*/
	CFileFind file;
	char thistime[30];
	struct tm *ltime;
	memset(filepath,0,512);
	memset(filename,0,64);

	if(!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"),NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime=localtime(&nowtime);
	strftime(thistime,sizeof(thistime),"%Y%m%d %H%M%S",ltime);	
	strcpy(filepath,"SavedData\\");
	strcat(filename,thistime);
	strcat(filename,".lix");

	strcat(filepath,filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if(dumpfile==NULL)
	{
		MessageBox(_T("File creation error!"));
		return -1; 
	}

	pcap_freealldevs(alldev);	

	/*Receive data, the new thread*/
	LPDWORD threadCap=NULL;
	m_ThreadHandle=CreateThread(NULL,0,lixsinff_CapThread,this,0,threadCap);
	if(m_ThreadHandle==NULL)
	{
		int code=GetLastError();
		CString str;
		str.Format(_T("Create thread error code %d."),code);
		MessageBox(str);
		return -1;
	}
	return 1;
}

DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter)
{
	int res,nItem ;
	struct tm *ltime;
	CString timestr,buf,srcMac,destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;	 //Data Header
	const u_char *pkt_data=NULL,*pData=NULL;  //Byte Flow of data received
	u_char *ppkt_data;
	
	Cmcf6Dlg *pthis = (Cmcf6Dlg*) lpParameter;
	if(NULL == pthis->m_ThreadHandle)
	{
		MessageBox(NULL,_T("Thread Handle Error"),_T("Prompt"),MB_OK);
		return -1;
	}
	
	while((res = pcap_next_ex( pthis->adhandle, &header, &pkt_data)) >= 0)
	{
		if(res == 0)				//Timeout
			continue;
		
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));		
		memset(data,0,sizeof(struct datapkt));

		if(NULL == data)
		{
			MessageBox(NULL,_T("Space is full, can not receive new packet"),_T("Error"),MB_OK);
			return -1;
		}

 	    //Error analysis or processing of the received data packet is not within the scope of
		if(analyze_frame(pkt_data,data,&(pthis->npacket))<0)
			continue;  
		
		//Save the data packets to the open file
		if(pthis->dumpfile!=NULL)
		{
			pcap_dump((unsigned char*)pthis->dumpfile,header,pkt_data);
		}

		//Updating various packet count
		pthis->lixsniff_updateNPacket();

		//The data is loaded into a localized list in order to later use		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data,pkt_data,header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);
	
		/*Preprocessing£¬Obrained Time¡¢Length*/
		data->len = header->len; //The length of the data 
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year+1900;
		data->time[1] = ltime->tm_mon+1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*For the newly received data packet to create a new item in the listControl*/
		buf.Format(_T("%d"),pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt,buf);

		/*SHOW TIMESTAMPS*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
			data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem,1,timestr);
		//pthis->m_listCtrl.setitem
		
		/*SHOW LENGTH*/
		buf.Empty();
		buf.Format(_T("%d"),data->len);
		pthis->m_listCtrl.SetItemText(nItem,2,buf);

		/*SHOW SOURCE MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
							data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem,3,buf);

		/*SHOW DESTINATION MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
							data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem,4,buf);

		/*Obtained PROTOCOL*/
		pthis->m_listCtrl.SetItemText(nItem,5,CString(data->pktType));

		/*Obtained SOURCE IP*/
		buf.Empty();
		if(0x0806== data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
				data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);			
		}else if(0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd ==data->ethh->type ){
			int n;
			for(n=0;n<8;n++)
			{			
				if(n<=6)
					buf.AppendFormat(_T("%02x:"),data->iph6->saddr[n]);		
				else
					buf.AppendFormat(_T("%02x"),data->iph6->saddr[n]);		
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,6,buf);

		/*Obtained DESTINATION IP*/
		buf.Empty();
		if(0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
				data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);			
		}else if(0x0800 == data->ethh->type){
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd ==data->ethh->type ){
			int n;
			for(n=0;n<8;n++)
			{			
				if(n<=6)
					buf.AppendFormat(_T("%02x:"),data->iph6->daddr[n]);		
				else
					buf.AppendFormat(_T("%02x"),data->iph6->daddr[n]);		
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,7,buf);
	
		/*Count on Package*/
		pthis->npkt++;
	
	}
	return 1;
}

//UPDATES
int Cmcf6Dlg::lixsniff_updateEdit(int index)
{
	POSITION localpos,netpos;
	localpos = this->m_localDataList.FindIndex(index);
	netpos = this->m_netDataList.FindIndex(index);

	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	u_char * net_data = (u_char*)(this->m_netDataList.GetAt(netpos));

	CString buf;
	print_packet_hex(net_data,local_data->len,&buf);
	//this-
	this->m_edit.SetWindowText(buf);

	return 1;
}

//Update Statistics
int Cmcf6Dlg::lixsniff_updateNPacket()
{
		CString str_num;		
		str_num.Format(_T("%d"),this->npacket.n_arp);
		this->m_editNArp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_http);
		this->m_editNHttp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_icmp);
		this->m_editNIcmp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_ip6);
		this->m_editNIp.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_other);
		this->m_editNOther.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_sum);
		this->m_editNSum.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_tcp);
		this->m_editNTcp.SetWindowText(str_num);
		
		str_num.Format(_T("%d"),this->npacket.n_udp);
		this->m_editNUdp.SetWindowText(str_num);
	
		str_num.Format(_T("%d"),this->npacket.n_ip);
		this->m_editNIpv4.SetWindowText(str_num);

		str_num.Format(_T("%d"),this->npacket.n_icmp6);
		this->m_editIcmpv6.SetWindowText(str_num);

		return 1;
}

//Update the tree control
int Cmcf6Dlg::lixsniff_updateTree(int index)
{
	POSITION localpos;
	CString str;
	int i;
	
	this->m_treeCtrl.DeleteAllItems();

	localpos = this->m_localDataList.FindIndex(index);
	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	
	HTREEITEM root = this->m_treeCtrl.GetRootItem();
	str.Format(_T("Receiving %d packet"),index+1);
	HTREEITEM data = this->m_treeCtrl.InsertItem(str,root);

	/*Processing frame data*/
	HTREEITEM frame = this->m_treeCtrl.InsertItem(_T("Data Link Layer"),data);
	//SOURCE MAC
	str.Format(_T("SOURCE MAC£º"));
	for(i=0;i<6;i++)
	{
		if(i<=4)
			str.AppendFormat(_T("%02x-"),local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"),local_data->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str,frame);
	//DESTINATION MAC
	str.Format(_T("DESTINATION MAC£º"));
	for(i=0;i<6;i++)
	{
		if(i<=4)
			str.AppendFormat(_T("%02x-"),local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"),local_data->ethh->dest[i]);
	}
	this->m_treeCtrl.InsertItem(str,frame);
	//Type
	str.Format(_T("Type£º0x%02x"),local_data->ethh->type);
	this->m_treeCtrl.InsertItem(str,frame);

	/*Processing IP¡¢ARP¡¢IPv6 Packet*/
	if(0x0806 == local_data->ethh->type)							//ARP
	{
		HTREEITEM arp = this->m_treeCtrl.InsertItem(_T("ARP PROTOCOL Header"),data);
		str.Format(_T("Hardware Type£º%d"),local_data->arph->ar_hrd);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("PROTOCOL Type£º0x%02x"),local_data->arph->ar_pro);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("Hardware Address LENGTH£º%d"),local_data->arph->ar_hln);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("PROTOCOL Address LENGTH£º%d"),local_data->arph->ar_pln);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("Operation Code£º%d"),local_data->arph->ar_op);
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Sender MAC£º"));
		for(i=0;i<6;i++)
		{
			if(i<=4)
				str.AppendFormat(_T("%02x-"),local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"),local_data->arph->ar_srcmac[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Sender IP£º"),local_data->arph->ar_hln);
		for(i=0;i<4;i++)
		{
			if(i<=2)
				str.AppendFormat(_T("%d."),local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"),local_data->arph->ar_srcip[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Recipient MAC£º"),local_data->arph->ar_hln);
		for(i=0;i<6;i++)
		{
			if(i<=4)
				str.AppendFormat(_T("%02x-"),local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02x"),local_data->arph->ar_destmac[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Recipien tIP£º"),local_data->arph->ar_hln);
		for(i=0;i<4;i++)
		{
			if(i<=2)
				str.AppendFormat(_T("%d."),local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"),local_data->arph->ar_destip[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

	}else if(0x0800 == local_data->ethh->type){					//IP
		
		HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IPPROTOCOLHeader"),data);

		str.Format(_T("Version£º%d"),local_data->iph->version);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("IPHeader Length£º%d"),local_data->iph->ihl);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Service Type£º%d"),local_data->iph->tos);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Total LENGTH£º%d"),local_data->iph->tlen);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Identity£º0x%02x"),local_data->iph->id);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Segment Offset£º%d"),local_data->iph->frag_off);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Lifetime£º%d"),local_data->iph->ttl);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("PROTOCOL£º%d"),local_data->iph->proto);
		this->m_treeCtrl.InsertItem(str,ip);		
		str.Format(_T("Header Checksum£º0x%02x"),local_data->iph->check);
		this->m_treeCtrl.InsertItem(str,ip);

		str.Format(_T("SOURCE IP£º"));
		struct in_addr in;
		in.S_un.S_addr = local_data->iph->saddr;		
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str,ip);

		str.Format(_T("DESTINATION IP£º"));
		in.S_un.S_addr = local_data->iph->daddr;		
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str,ip);

		/*Transport Layer Processing ICMP¡¢UDP¡¢TCP*/
		if(1 == local_data->iph->proto )	//ICMP
		{
			HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMPPROTOCOLHeader"),data);
				
			str.Format(_T("Type:%d"),local_data->icmph->type);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("Code:%d"),local_data->icmph->code);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("Number:%d"),local_data->icmph->seq);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("Checksum:%d"),local_data->icmph->chksum);
			this->m_treeCtrl.InsertItem(str,icmp);

		}else if(6 == local_data->iph->proto){				//TCP
			
			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCPPROTOCOLHeader"),data);

			str.Format(_T("  SOURCE Port:%d"),local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  DESTINATION Port:%d"),local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Serial Number:0x%02x"),local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Confirmation Number:%d"),local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Header LENGTH:%d"),local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T(" +FLAG"),tcp);
	
			str.Format(_T("cwr %d"),local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ece %d"),local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("urg %d"),local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ack %d"),local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("psh %d"),local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("rst %d"),local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("syn %d"),local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("fin %d"),local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str,flag);

			str.Format(_T("  Urgent Pointer:%d"),local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Checksum:0x%02x"),local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Option:%d"),local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str,tcp);
		}else if(17 == local_data->iph->proto){				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDPPROTOCOLHeader"),data);
				
			str.Format(_T("SOURCE Port:%d"),local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("DESTINATION Port:%d"),local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Total LENGTH:%d"),local_data->udph->len);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Checksum:0x%02x"),local_data->udph->check);
			this->m_treeCtrl.InsertItem(str,udp);
		}
	}else if(0x86dd == local_data->ethh->type){		//IPv6
		HTREEITEM ip6 = this->m_treeCtrl.InsertItem(_T("IPv6PROTOCOLHeader"),data);
		
		//////////////////////////////////////////////////////////////////////////////////////////
		str.Format(_T("Version:%d"),local_data->iph6->flowtype);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("Flow Type:%d"),local_data->iph6->version);
		this->m_treeCtrl.InsertItem(str,ip6);
		///////////////////////////////////////////////////////////////////////////////////////////
		str.Format(_T("Flow Label:%d"),local_data->iph6->flowid);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("Payload LENGTH:%d"),local_data->iph6->plen);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("Next Header:0x%02x"),local_data->iph6->nh);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("Hop Limit:%d"),local_data->iph6->hlim);
		this->m_treeCtrl.InsertItem(str,ip6);

		str.Format(_T("SOURCE Address:"));
		int n;
		for(n=0;n<8;n++)
		{			
			if(n<=6)
				str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);		
			else
				str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);		
		}	
		this->m_treeCtrl.InsertItem(str,ip6);

		str.Format(_T("DESTINATION Address:"));
		for(n=0;n<8;n++)
		{			
			if(n<=6)
				str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);		
			else
				str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);		
		}	
		this->m_treeCtrl.InsertItem(str,ip6);

		/*Transport layer processing ICMPv6¡¢UDP¡¢TCP*/
		if(0x3a== local_data->iph6->nh )	//ICMPv6
		{
			HTREEITEM icmp6 = this->m_treeCtrl.InsertItem(_T("ICMPv6PROTOCOLHeader"),data);
				
			str.Format(_T("Type:%d"),local_data->icmph6->type);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("Code:%d"),local_data->icmph6->code);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("Number:%d"),local_data->icmph6->seq);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("Checksum:%d"),local_data->icmph6->chksum);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("Option-Type:%d"),local_data->icmph6->op_type);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("Option-LENGTH%d"),local_data->icmph6->op_len);
			this->m_treeCtrl.InsertItem(str,icmp6);
			str.Format(_T("Option-LinkLayerAddress:"));
			int i;
			for(i=0;i<6;i++)
			{
				if(i<=4)				
					str.AppendFormat(_T("%02x-"),local_data->icmph6->op_ethaddr[i]);
				else
					str.AppendFormat(_T("%02x"),local_data->icmph6->op_ethaddr[i]);
			}
			this->m_treeCtrl.InsertItem(str,icmp6);

		}else if(0x06 == local_data->iph6->nh){				//TCP
			
			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCPPROTOCOLHeader"),data);

			str.Format(_T("  SOURCE Port:%d"),local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  DESTINATION Port:%d"),local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Serial Number:0x%02x"),local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Confirmation Number:%d"),local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Header LENGTH:%d"),local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T("FLAG"),tcp);
	
			str.Format(_T("cwr %d"),local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ece %d"),local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("urg %d"),local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ack %d"),local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("psh %d"),local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("rst %d"),local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("syn %d"),local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("fin %d"),local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str,flag);

			str.Format(_T("  Urgent Pointer:%d"),local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Checksum:0x%02x"),local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Option:%d"),local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str,tcp);
		}else if(0x11== local_data->iph6->nh){				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDPPROTOCOLHeader"),data);

			str.Format(_T("SOURCEPort:%d"),local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("DESTINATIONPort:%d"),local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("TotalLENGTH:%d"),local_data->udph->len);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Checksum:0x%02x"),local_data->udph->check);
			this->m_treeCtrl.InsertItem(str,udp);
		}
	}

	return 1;
}


int Cmcf6Dlg::lixsniff_saveFile()
{
	CFileFind find;
	if(NULL==find.FindFile(CString(filepath)))
	{
		MessageBox(_T("Saving FILE Encountered an Unknown expectetion"));
		return -1;
	}

	//Open File dialog box
	 CFileDialog   FileDlg(FALSE,_T(".lix"),NULL,OFN_HIDEREADONLY   |   OFN_OVERWRITEPROMPT);   
	 FileDlg.m_ofn.lpstrInitialDir=_T("c:\\");   
	 if(FileDlg.DoModal()==IDOK)   
	 {   
			CopyFile(CString(filepath),FileDlg.GetPathName(),TRUE);
	 }
	return 1;
}

int Cmcf6Dlg::lixsniff_readFile(CString path)
{
	int res,nItem,i ;
	struct tm *ltime;
	CString timestr,buf,srcMac,destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;	//PacketHeader
	const u_char *pkt_data=NULL;     //Received byte network Flow Data
	u_char *ppkt_data;

	Cmcf6Dlg *pthis =this;	//Some code transformation from ipv6sniffer_CapThread£¬To save workload£¬So keep pthis pointer
	pcap_t *fp;
	
//First Processing click the path, open the file when pcap_open_offline use
	//Paths need to use char * Type, can not use char CString cast after *
	int len = path.GetLength()+1;   //////////////Note that this detail, we must add one, otherwise it will go wrong
	char* charpath = (char *)malloc(len);
	memset(charpath,0,len);
	if(NULL==charpath)
		return -1;

	for(i=0;i<len;i++)
		charpath[i] = (char)path.GetAt(i);
	
	//Open the relevant file
	if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, errbuf)) == NULL)
	{
		MessageBox(_T("Open File Error")+CString(errbuf));
		return -1;
	}
	
	while((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));		
		memset(data,0,sizeof(struct datapkt));

		if(NULL == data)
		{
			MessageBox(_T("Space is full, can not receive new packet"));
			return  -1;
		}

//Error analysis or processing of the received data packet is not within the scope of
		if(analyze_frame(pkt_data,data,&(pthis->npacket))<0)
			 continue;
		
 //Updating various packet count
		pthis->lixsniff_updateNPacket();

	//The data is loaded into a localized list in order to later use
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data,pkt_data,header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);
	
		/*Preprocessing£¬Obtained Time¡¢Length*/
		data->len = header->len; //The length of the data received link
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year+1900;
		data->time[1] = ltime->tm_mon+1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

/*For the newly received data packet to create a new item in the listControl*/
		buf.Format(_T("%d"),pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt,buf);

		/*SHOW TIME Stamps*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
			data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem,1,timestr);
		
		/*SHOW LENGTH*/
		buf.Empty();
		buf.Format(_T("%d"),data->len);
		pthis->m_listCtrl.SetItemText(nItem,2,buf);

		/*SHOW SOURCEMAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
							data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem,3,buf);

		/*SHOW DESTINATIONMAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
							data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem,4,buf);

		/*Obtained PROTOCOL*/
		pthis->m_listCtrl.SetItemText(nItem,5,CString(data->pktType));

		/*Obtained SOURCE IP*/
		buf.Empty();
		if(0x0806== data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
				data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);			
		}else  if(0x0800 == data->ethh->type){
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd == data->ethh->type){
			int i;
			for(i=0;i<8;i++)
			{
				if(i<=6)
					buf.AppendFormat(_T("%02x-"),data->iph6->saddr[i]);
				else
					buf.AppendFormat(_T("%02x"),data->iph6->saddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,6,buf);

		/*Obtained DESTINATION IP*/
		buf.Empty();
		if(0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
				data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);			
		}else if(0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd == data->ethh->type){
			int i;
			for(i=0;i<8;i++)
			{
				if(i<=6)

					buf.AppendFormat(_T("%02x-"),data->iph6->daddr[i]);
				else
					buf.AppendFormat(_T("%02x"),data->iph6->daddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,7,buf);
	
		/*Count on Package*/
		pthis->npkt++;
	}

	pcap_close(fp);

	return 1;
}
