#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>

#include <asm/uaccess.h>
#include <asm/segment.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Artemy Urodovskikh");
MODULE_DESCRIPTION("MiniFS driver module that uses VFS backend");
MODULE_VERSION("0.01");

#define DEVICE_NAME "minifs_device"
#define MSG "Loaded minifs and minifs char device\n"
#define MSG_BUFFER_LEN 20000
#define BUF_LEN 20000

#define FILESIZE 100
#define BLOCK_LIST_SIZE 434

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

typedef struct inode_mini {
	char filename[FILESIZE];
	char is_directory;
	int created;
	int accepted;
	int updated;

	int uid;
	int gid;

	int am;

	// data = concat: block_offset + c*block_size for c in data
	short data[BLOCK_LIST_SIZE]; // unsigned long long for usage as offset

	int inode_id;
} in;

typedef struct superblock {
	int inode_counter;
} superblock_t;

#define INODE_MAP_SIZE sizeof(int)*64
#define BLOCK_MAP_SIZE sizeof(int)*241

#define INODES 2046
#define BLOCKSIZE 4096
#define INODE_MAP_OFFSET sizeof(int)+sizeof(superblock_t)
#define BLOCK_MAP_OFFSET INODE_MAP_OFFSET+INODE_MAP_SIZE
#define INODE_OFFSET BLOCK_MAP_OFFSET+BLOCK_MAP_SIZE
#define BLOCK_OFFSET INODE_OFFSET+sizeof(in)*INODES+772
#define DIR_LIST_SIZE BLOCKSIZE/sizeof(short)

// TODO: forward decl
in * get_inode_rec(in *, superblock_t *, struct file *, char *);
in * create_inode(char *, int, struct file *);
// TODO: df -ah 


static int major_num;
static int device_open_count = 0;
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;

static char Message[BUF_LEN];
static char *Message_Ptr;

int *inode_bitmap;
int *block_bitmap;

#define set_bit(A,k)     ( A[(k)/32] |= (1 << ((k)%32)) )
#define unset_bit(A,k)   ( A[(k)/32] &= ~(1 << ((k)%32)) )
#define get_bit(A,k)    ( A[(k)/32] & (1 << ((k)%32)) )

struct file *file_open(const char *path, int flags, int rights) {
	struct file *filp = NULL;
	int err = 0;

	filp = filp_open(path, flags, rights);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		printk("%d\n", err);
		return NULL;
	}
	return filp;
}

int file_sync(struct file *file) {
	vfs_fsync(file, 0);
	return 0;
}

void file_close(struct file *file) {
	filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset, void *data, unsigned int size) {
	int ret;

	ret = kernel_read(file, data, size, &offset);

	return ret;
}

int file_write(struct file *file, unsigned long long offset, void *data, unsigned int size) {
	int ret;

	ret = kernel_write(file, data, size, &offset);
	vfs_llseek(file, 0, SEEK_SET);
	file_sync(file);

	return ret;
}


int * read_bitmap(int offset, int bitmap_size) {
	int ret_;

	struct file *res = file_open("/home/rtmy/me", O_RDWR, 0);

	int * bitmap = kmalloc(bitmap_size, GFP_KERNEL);
	ret_ = file_read(res, offset, bitmap, bitmap_size);

	printk("in newly read %d", get_bit(bitmap, 0));

	return bitmap;
}

void write_bitmap(int offset, int bitmap_size, int *bitmap) {
	int ret_;

	struct file *res = file_open("/home/rtmy/me", O_RDWR, 0);

	printk("wroating %d", get_bit(bitmap, 0));

	ret_ = file_write(res, offset, bitmap, bitmap_size);

	int * bm = read_bitmap(offset, bitmap_size);
	printk("after wrote %d", get_bit(bm, 0));
}

void set_bitmap(int offset, int bitmap_size, int pos) {
	int *bitmap = read_bitmap(offset, bitmap_size);
	set_bit(bitmap, pos);
	printk("ok set %d", get_bit(bitmap, pos));
	write_bitmap(offset, bitmap_size, bitmap);
}

void unset_bitmap(int offset, int bitmap_size, int pos) {
	int *bitmap = read_bitmap(offset, bitmap_size);
	unset_bit(bitmap, pos);
	write_bitmap(offset, bitmap_size, bitmap);
}

int get_bitmap(int offset, int bitmap_size, int pos) {
	int *bitmap = read_bitmap(offset, bitmap_size);
	return get_bit(bitmap, pos);
}

int acquire_free_block(in *node) {
	// TODO: search closer to node blocks 
	int i;
	int block = -10;
	int ret_;
	for (i = 0; i < BLOCK_MAP_SIZE; i++) {
		if (!(get_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, i))) {
			block = i;	
			break;
		}
	}
	printk("have block %d", block);

	if (block > 0) {
		set_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, block);

		for (i = 0; (i < BLOCK_LIST_SIZE) && (node->data[i] != 0x00); i++) {
			;;
		}
		node->data[i] = block;

		struct file *ret = file_open("/home/rtmy/me", O_RDWR, 0);
		ret_ = file_write(ret, (node->inode_id)*sizeof(in)+INODE_OFFSET, node, sizeof(in));

		return block;
	}
	printk("bbmg!");
	return -1;
}

void free_blocks(in *node) {
	struct file *ret = file_open("/home/rtmy/me", O_RDWR, 0);

	int b;
	int ret_;
	int i;
	for (i = 0; (i < BLOCK_LIST_SIZE) && (node->data[i] != 0x00); i++) {
			b = node->data[i];
			unset_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, b);

			node->data[i] = 0x00;
	}

	ret_ = file_write(ret, (node->inode_id)*sizeof(in)+INODE_OFFSET, node, sizeof(in));
}

static struct file_operations file_ops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

static ssize_t device_read(struct file *filp, char *buffer, size_t len, loff_t *offset) {
	int bytes_read = 0;

	if (*msg_ptr == 0) {
		msg_ptr = msg_buffer;
	}

	while (len && *msg_ptr) {
		put_user(*(msg_ptr++), buffer++);
		len--;
		bytes_read++;
	}

	return bytes_read;

}

static int device_open(struct inode *inode, struct file *file) {
	if (device_open_count) {
		return -EBUSY;
	}
	device_open_count++;
	try_module_get(THIS_MODULE);
	return 0;
}

static int device_release(struct inode *inode, struct file *file) {
	device_open_count--;
	module_put(THIS_MODULE);

	return 0;
}


in * get_inode(char *path) {
	int ret_;

	struct file *ret = file_open("/home/rtmy/me", O_RDWR, 0);

	int *activation_value = kmalloc(sizeof(int), GFP_KERNEL);
	ret_ = file_read(ret, 0, activation_value, sizeof(int));

	printk("Formatted %d\n", *activation_value);

	if (*activation_value == 1) {

		superblock_t *sb = kmalloc(sizeof(superblock_t), GFP_KERNEL);
		ret_ = file_read(ret, sizeof(int), sb, sizeof(superblock_t));
		in *root_node = kmalloc(sizeof(in), GFP_KERNEL);
		ret_ = file_read(ret, INODE_OFFSET, root_node, sizeof(in));
		if (!(strcmp(path, "/")) || strlen(path) == 1) {
			return root_node;
		} else {
			in *node = get_inode_rec(root_node, sb, ret, path+sizeof(char));
			return node;
		}

	} else {
		int activation_byte = 1;
		ret_ = file_write(ret, 0, &activation_byte, sizeof(int));
		superblock_t sb = {
		       .inode_counter = 1
		};
		ret_ = file_write(ret, sizeof(int), &sb, sizeof(superblock_t));
		in root = {
			.filename = "/",
			.is_directory = (char) 1,
			.data = { 0 },
			.inode_id = 1
		};
		ret_ = file_write(ret, INODE_OFFSET, &root, sizeof(in));

		short dir_list[DIR_LIST_SIZE] = { 0x00 };
		ret_ = file_write(ret, BLOCK_OFFSET, &dir_list, sizeof(dir_list));

		printk("form");
		set_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, 0);
		printk("opening %d", get_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, 0));
		return &root;
	}

	// file_close(ret);
	return 0;
}

in * get_inode_rec(in *root, superblock_t *sb, struct file *ret, char *path) {
	// TODO: (cd) ignore everything, return inode
	// TODO: (mkdir) or (touch) depending on command, create different inode types
	printk("got in rec");

	int ret_;
	in *node;
	if (!(strchr(path+sizeof(char), '/'))) {
		char * filename = path;

		int block_pointer = 0x00;
		int ic = sb->inode_counter;
		int i;

		for (i = 0; (i < BLOCK_LIST_SIZE) && (root->data[i] != 0x00); i++) {
			block_pointer = root->data[i];
		}
		
		//if (block_pointer == 0x00) {
			// its either root dir or empty file

			if (root->is_directory) {
				short *dir_list = kmalloc(BLOCKSIZE, GFP_KERNEL);
				ret_ = file_read(ret, BLOCK_OFFSET+block_pointer*BLOCKSIZE, dir_list, BLOCKSIZE);

				// if dir_list empty:
				if (dir_list[0] == 0x00) {
					node = create_inode(filename, ic, ret);

					dir_list[0] = ic;
					ret_ = file_write(ret, BLOCK_OFFSET+block_pointer*BLOCKSIZE, dir_list, BLOCKSIZE);

					// TODO: to a distinct fn
					++sb->inode_counter;
					printk("new sb %d", sb->inode_counter);
					ret_ = file_write(ret, sizeof(int), sb, sizeof(superblock_t));
					
					return node;
				} else {
					in *node = kmalloc(sizeof(in), GFP_KERNEL);
					for (i = 0; (i < DIR_LIST_SIZE) && (dir_list[i] != 0x00); i++) {
						ret_ = file_read(ret, INODE_OFFSET+sizeof(in)*dir_list[i], node, sizeof(in));
						printk("read node %d", ret_);
						if (!(strcmp(filename, node->filename))) {
							printk("File exists, returning\n");
							return node;
						}
					}

					// if mkdir, node->is_directory = 1
					node = create_inode(filename, ic, ret);
					dir_list[i] = node->inode_id;
					printk("dl %d", node->inode_id);

					ret_ = file_write(ret, BLOCK_OFFSET+block_pointer*BLOCKSIZE, dir_list, BLOCKSIZE);

					// TODO: to a distinct fn
					++sb->inode_counter;
					printk("new sb %d", sb->inode_counter);
					ret_ = file_write(ret, sizeof(int), sb, sizeof(superblock_t));

					return node; 
				}

				printk("111");
			} else {
				return root;
				printk("is it dir? %p %s", root->is_directory, root->filename);
				printk("000");
				// TODO: (cat) logic for file reading
			}

		//} else {
		//	printk("222");
			// TODO: depending on command, may be >>
		//}
	}
	
	// path = in, rest
	// while rest:
	//  get_inode_rec(rest)
	return 0x00;
}

in * create_inode(char *filename, int ic, struct file *ret) {
	// TODO: use inode map

	int ret_;
	in node = {
		.data = { 0 },
		.inode_id = ic,
		// TODO: remove kostyl
		.is_directory = (char) 1
	};

	in *node_ptr = kmalloc(sizeof(in), GFP_KERNEL);
	memcpy(node_ptr, &node, sizeof(in));

	strcpy(node.filename, filename);
	ret_ = file_write(ret, (ic)*sizeof(in)+INODE_OFFSET, &node, sizeof(in));

	return node_ptr;
}

int write_to_file(in *node, char *data) {
	struct file *res = file_open("/home/rtmy/me", O_RDWR, 0);
	int ret_ = 0;
	int i;
	int b = node->data[0];
	int s;

	for (s = 0; (s < BLOCK_LIST_SIZE) && (node->data[s] != 0x00); s++) {
			;;
	}
	printk("ss %d", s);
	for (i = 0; (i < strlen(data)*sizeof(char)); i+=BLOCKSIZE) {
		if (i/BLOCKSIZE >= s) {
			printk("ack new %d %d", i, s);
			b = acquire_free_block(node);
		}
		ret_ += file_write(res, BLOCK_OFFSET+((short) b)*BLOCKSIZE, data+i, BLOCKSIZE);
	}

	printk("sss %d", node->data[0]);

	printk("wrote %d bytes\n", ret_);

	return ret_;
}

int read_from_file(in *node, char *data) {
	struct file *res = file_open("/home/rtmy/me", O_RDWR, 0);
	int ret_ = 0;
	int i;
	int j;
	int b;

	printk("from node %d", node->data[0]);

	for (i = 0; (i < BLOCK_LIST_SIZE) && (node->data[i] != 0x00); i++) {
			;;
	}

	char *buf = kmalloc(BLOCKSIZE*i, GFP_KERNEL);
	printk("buffered %d", i);

	// and for each block in node->data read it to buffer

	for (j = 0; j < i; j+=1) {
		b = node->data[j];
		ret_ += file_read(res, BLOCK_OFFSET+((short) b)*BLOCKSIZE, buf+BLOCKSIZE*j, BLOCKSIZE);
	}

	printk("JJ %.*s", ret_, buf);

	//ret_ = file_read(res,  BLOCK_OFFSET+((short) node->data[0])*BLOCKSIZE, buf, BLOCKSIZE);

	printk("read %d bytes \n", ret_);
	printk("content: %s \n", buf);

	return ret_;
}

// int remove_inode(node) {
// 	unset_bitmap(inode_bitmap, node->inode_id);

// 	parent_node = get_inode(parent);
// 	// look for inode_id in parent_node -> data -> dir_list
// 	// set to zero
// 	// write parent_node

// }

// int remove_file(f) {
// 	inode = get_inode(f);
// 	free_blocks(node);

// }

// int copy_file(old, new) {
// 	i_old = get_inode(old);
// 	content = read_from_file(old);
// 	get_inode(new);
// 	write_to_file(content);
// }

// int move_file(old, new) {
// 	copy_file(old, new);

// }

static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset) {
	int i;
	int ret_;

	for (i = 0; (i < len) && (i < BUF_LEN); i++) {
		get_user(Message[i], buffer + i);
	}
	
	if (Message[0] == 'a') {
		printk("touch");
		printk("opening %d", get_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, 0));
		// todo function of parsing touch message
		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		char am = Message[i+1];

		in *node = get_inode(path);
		printk("created inode %p", node);

	} else if (Message[0] == '>') {

		// TODO: function of parsing touch message
		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		char am = Message[i+1];

		in *node = get_inode(path);
		// TODO: check if exists

		char *data = kmalloc(BUF_LEN, GFP_KERNEL);

		int j = 0;

		++i;
		while ((Message[i] != 0) && (i < BUF_LEN)) {
			data[j] = Message[i];
			++i;
			++j;
		}

		printk("payload %s", data);
		printk("len %d", strlen(data));
		printk("target %p", node);

		ret_ = write_to_file(node, data);

	} else if (Message[0] == 'c') {
		// todo function of parsing touch message
		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		printk("read %s", path);
		in *node = get_inode(path);

		char *data;

		printk("have inode %p", node);

		read_from_file(node, data);

	}

	// cp 
	// copy inode
	// insert inode to target descendants

	Message_Ptr = Message;

	return i;
}

static int __init lkm_example_init(void) {
    strncpy(msg_buffer, MSG, MSG_BUFFER_LEN);

	msg_ptr = msg_buffer;
	major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
	if (major_num < 0) {
		printk(KERN_ALERT "Could not register: %d\n", major_num);
		return major_num;
	}
	printk(KERN_INFO "%s module loaded with device major number %d\n", DEVICE_NAME, major_num);

	return 0;
}

static void __exit lkm_example_exit(void) {
	unregister_chrdev(major_num, DEVICE_NAME);
	printk(KERN_INFO "Unloaded module\n");
}


module_init(lkm_example_init);
module_exit(lkm_example_exit);
