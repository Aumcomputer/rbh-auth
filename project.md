const pool_comcenter =  mysql.createPool({
  host: process.env.DB_COMCENTER_HOST,
  user: process.env.DB_COMCENTER_USER,
  password: process.env.DB_COMCENTER_PASSWORD,
  database: "teamcom3_pis",
  charset: 'tis620',
  waitForConnections: true


//sql สำหรับดึง lineid และ cid จาก username
select u.fullname , u.userId as lineid, u.cid 
from users u 
where u.username = ?

async function sendMophAlert(payload) {
    
    try {
        const response = await fetch(apiMOPHUrl, {
            method: 'POST',
            headers: {
                'client-key': MOPH_CLIENT_KEY,
                'secret-key': MOPH_SECRET_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload), 
        });
        //console.log(payload)
        const data = await response.json();
//data ที่ตอบกลับมี 3 รูปแบบ
{ app_message: 'Success.', line_message: 'No Cid', message_code: 200 }  // มี app หมอพร้อม แต่ ไม่มี line หมอพร้อม
{ app_message: 'Success.', line_message: 'success', message_code: 200 }//มี app หมอพร้อม และ มีline หมอพร้อม
{ message: 'CID Not found', message_code: 500, reason: {} }  //ไม่มี app หมอพร้อม และ ไม่มี line หมอพร้อม
        if (response.ok) { 
            //console.log(payload.cid);
            console.log(payload.cid+' | MOPH Alert success:', data);
            return { success: true, data: data };
        } else {
            //console.error(payload.cid);
            console.error(payload.cid+' | MOPH Alert  failed (API Error):', data);
            
            return { success: false, error: data };
        }

    } catch (error) {
        //console.error(payload.cid);
        console.error(payload.cid+' | MOPH Alert  failed (Network/Fetch Error):', error.message);
        return { success: false, error: { message: error.message } };
    }
}

async function sendLineRBHC(payload) {
    //console.log(payload.cid[0]);
    const userId = await getLineuseridByCid(payload.cid[0]);
     if (userId) 
     {
            const bodyData = {
            to: userId, 
            messages: [
              {
                type: 'text',
                text: payload.messages[0].text
              }
            ]
          };
            try {
                const response = await fetch(apiLINEUrl, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${RBHC_LINE_TOKEN}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(bodyData), 
                });
                //console.log(userId)
                //console.log(bodyData)
                const data = await response.json();

                if (response.ok) { 
                    //console.log(payload.cid);
                    console.log(payload.cid+' | Line message success:', data);
                    return { success: true, data: data };
                } else {
                    //console.error(payload.cid);
                    console.error(payload.cid+' | Line message failed (API Error):', data);
                    
                    return { success: false, error: data };
                }

            } catch (error) {
                //console.error(payload.cid);
                console.error(payload.cid+' | Line message failed (Network/Fetch Error):', error.message);
                return { success: false, error: { message: error.message } };
            }
  }
  else console.error(payload.cid +"Not register RBHC");
}


function createPayload(doctorGroup) {
    const { DoctorName, CID, AnCount, Visits } = doctorGroup;

    // 1. สร้างส่วนของรายการ AN/DaysCount
    // ตัวอย่าง: "AN: 680042971 เวลา 8 วัน"
    const visitLines = Visits.map(visit => 
        `AN: ${visit.an} เวลา ${visit.DaysCount} วัน`
    );

    // 2. สร้างข้อความสำหรับ Plain Text (ใช้ \n ขึ้นบรรทัดใหม่)
    const textDetails = visitLines.join('\n');
    const fullText = 
        `${DoctorName}\n` +
        `แจ้งเตือนสรุปชาร์ท จำนวน ${AnCount} รายการ\n` +
        textDetails;

    // 3. สร้างข้อความสำหรับ HTML (ใช้ <br> ขึ้นบรรทัดใหม่)
    const htmlDetails = visitLines.join('<br>');
    const fullHtml = 
        `<div>` +
        `${DoctorName}<br>` + 
        `แจ้งเตือนสรุปชาร์ท จำนวน ${AnCount} รายการ <br>` + 
        htmlDetails + 
        `</div>`;

    // 4. สร้าง Payload สุดท้าย
    const payload = {
        "cid": [CID], 
        "messages": [
            {
                "text": fullText,
                "type": "text"
            }
        ],
        "message_title": "แจ้งเตือนสรุปชาร์ท",
        "message_html": fullHtml,
        "message_text": "แจ้งเตือนสรุปชาร์ท", 
        "message_type": "HPT"
    };

    return payload;
}


