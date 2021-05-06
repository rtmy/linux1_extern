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
#define FILESYSTEM "/home/rtmy/me"

#define MSG "Loaded minifs and minifs char device\n"
#define MSG_BUFFER_LEN 2000
#define BUF_LEN 20000
#define FILESIZE 100
#define BLOCK_LIST_SIZE 434

#define INODE_MAP_SIZE sizeof(int)*64
#define BLOCK_MAP_SIZE sizeof(int)*241

#define INODES 2046
#define BLOCKSIZE 4096

#define INODE_MAP_OFFSET sizeof(int)+sizeof(superblock_t)
#define BLOCK_MAP_OFFSET INODE_MAP_OFFSET+INODE_MAP_SIZE
#define INODE_OFFSET BLOCK_MAP_OFFSET+BLOCK_MAP_SIZE
#define BLOCK_OFFSET INODE_OFFSET+sizeof(in)*INODES+772
#define DIR_LIST_SIZE BLOCKSIZE/sizeof(short)

#define set_bit(A,k)     ( A[(k)/32] |= (1 << ((k)%32)) )
#define unset_bit(A,k)   ( A[(k)/32] &= ~(1 << ((k)%32)) )
#define get_bit(A,k)    ( A[(k)/32] & (1 << ((k)%32)) )

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

	short data[BLOCK_LIST_SIZE];

	int inode_id;
} in;

typedef struct superblock {
	int inode_counter;
} superblock_t;


in * get_inode(char *, bool, bool);
in * get_inode_rec(in *, superblock_t *, struct file *, char *, bool, bool);
in * create_inode(char *, int, struct file *, bool);

static struct file_operations file_ops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};


static int major_num;
static int device_open_count = 0;
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;

static char Message[BUF_LEN];
static char *Message_Ptr;

int *inode_bitmap;
int *block_bitmap;

void * safe_alloc(int space) {
	void *ret;
	ret = kmalloc(space, GFP_KERNEL);
	if (ret == NULL) {
		printk("UNSAFE ALLOC");
		// TODO: unload module?
	}
	return ret;
}

struct file *file_open(const char *path, int flags, int rights) {
	struct file *filp = NULL;
	int err = 0;

	filp = filp_open(path, flags, rights);
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
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
	return kernel_read(file, data, size, &offset);
}

int file_write(struct file *file, unsigned long long offset, void *data, unsigned int size) {
	int ret;

	ret = kernel_write(file, data, size, &offset);
	vfs_llseek(file, 0, SEEK_SET);
	file_sync(file);

	return ret;
}

int * read_bitmap(int offset, int bitmap_size) {
	struct file *res = file_open(FILESYSTEM, O_RDWR, 0);

	int * bitmap = (int*) safe_alloc(bitmap_size);
	file_read(res, offset, bitmap, bitmap_size);
	if (bitmap == NULL)
		return NULL;

	file_close(res);

	return bitmap;
}

void write_bitmap(int offset, int bitmap_size, int *bitmap) {
	struct file *res = file_open(FILESYSTEM, O_RDWR, 0);
	file_write(res, offset, bitmap, bitmap_size);

	file_close(res);
}

int set_bitmap(int offset, int bitmap_size, int pos) {
	int *bitmap = read_bitmap(offset, bitmap_size);
	if (bitmap == NULL)
		return -1;
	set_bit(bitmap, pos);
	write_bitmap(offset, bitmap_size, bitmap);
	kfree(bitmap);
	return 0;
}

int unset_bitmap(int offset, int bitmap_size, int pos) {
	int *bitmap = read_bitmap(offset, bitmap_size);
	if (bitmap == NULL)
		return -1;
	unset_bit(bitmap, pos);
	write_bitmap(offset, bitmap_size, bitmap);
	kfree(bitmap);
	return 0;
}

int get_bitmap(int offset, int bitmap_size, int pos) {
	int *bitmap = read_bitmap(offset, bitmap_size);
	if (bitmap == NULL)
		return -1;
	kfree(bitmap);
	return get_bit(bitmap, pos);
}

int acquire_free_block(in *node) {
	// TODO: search closer to node blocks 
	int ret_, i;
	int block = -10;
	for (i = 0; i < BLOCK_MAP_SIZE; i++) {
		int bit = get_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, i);
		printk("%d bit is %d\n", i, bit);
		if (bit == -1)
			return -1;
		if (!(bit)) {
			block = i;	
			break;
		}
	}

	if (block > 0) {
		if (set_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, block))
			return -1;
		printk("wrote %d", get_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, block));

		for (i = 0; (i < BLOCK_LIST_SIZE) && (node->data[i] != 0x00); i++)
			;;
		node->data[i] = block;

		struct file *ret = file_open(FILESYSTEM, O_RDWR, 0);
		ret_ = file_write(ret, (node->inode_id)*sizeof(in)+INODE_OFFSET, node, sizeof(in));
		file_close(ret);

		return block;
	}
	return -1;
}

int free_blocks(in *node) {
	int b, ret_, i;

	struct file *ret = file_open(FILESYSTEM, O_RDWR, 0);

	for (i = 0; (i < BLOCK_LIST_SIZE) && (node->data[i] != 0x00); i++) {
			b = node->data[i];
			if (unset_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, b) == -1)
				return -1;

			node->data[i] = 0x00;
	}

	ret_ = file_write(ret, (node->inode_id)*sizeof(in)+INODE_OFFSET, node, sizeof(in));
	file_close(ret);
	return 0;
}

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

int write_msg(char* msg) {
	char * resp = (char*) safe_alloc(MSG_BUFFER_LEN);
	if (resp == NULL)
		return -1;
	snprintf(resp, strlen(msg)+1, "%s", msg);
	strncpy(msg_buffer, resp, MSG_BUFFER_LEN);
	kfree(resp);
	return 0;
}

in * get_inode(char *path, bool is_directory, bool create) {
	int ret_;

	struct file *ret = file_open(FILESYSTEM, O_RDWR, 0);

	int *activation_value = (int*) safe_alloc(sizeof(int));
	if (activation_value == NULL)
		return 0;
	ret_ = file_read(ret, 0, activation_value, sizeof(int));

	// char ans[] = "Formatted";
	// if (write_msg(ans))
		// return NULL;

	if (*activation_value == 1) {

		superblock_t *sb = (superblock_t*) safe_alloc(sizeof(superblock_t));
	if (sb == NULL)
		return NULL;
		ret_ = file_read(ret, sizeof(int), sb, sizeof(superblock_t));
		in *root_node = (in*) safe_alloc(sizeof(in));
	if (root_node == NULL)
		return NULL;
		ret_ = file_read(ret, INODE_OFFSET, root_node, sizeof(in));

 	if (!(strcmp(path, "/")) || strlen(path) == 1) {
 		return root_node;
 	} else {
 		in *node = get_inode_rec(root_node, sb, ret, path+sizeof(char), is_directory, create);
 		if (node == NULL)
 			return NULL;
 		return node;
 	}

	kfree(activation_value);
	kfree(sb);
	kfree(root_node);

	} else {
		int activation_byte = 1;
		ret_ = file_write(ret, 0, &activation_byte, sizeof(int));
		superblock_t sb = {
		       .inode_counter = 1
		};
		ret_ = file_write(ret, sizeof(int), &sb, sizeof(superblock_t));
		in root = {
			.filename = "/",
			.is_directory = 1,
			.data = { 0 },
			.inode_id = 1
		};
		ret_ = file_write(ret, INODE_OFFSET, &root, sizeof(in));

	 	short dir_list[DIR_LIST_SIZE] = { 0x00 };
	 	ret_ = file_write(ret, BLOCK_OFFSET, &dir_list, sizeof(dir_list));

		 	if (set_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, 0))
		 		return NULL;
		 	return &root;
	 }

	file_close(ret);
	return 0;
}

in * get_inode_rec(in *root, superblock_t *sb, struct file *ret, char *path, bool is_directory, bool create) {

	int ret_, i;
	in *node;
	char * slash_pos = strchr(path+sizeof(char), '/');
	if (!(slash_pos)) {
		char * filename = path;

		int block_pointer = 0x00;
		int ic = sb->inode_counter;

		for (i = 0; (i < BLOCK_LIST_SIZE) && (root->data[i] != 0x00); i++) {
			block_pointer = root->data[i];
		}

		if (root->is_directory) {
			short *dir_list = (short*) safe_alloc(BLOCKSIZE);
			ret_ = file_read(ret, BLOCK_OFFSET+block_pointer*BLOCKSIZE, dir_list, BLOCKSIZE);
			if (dir_list == NULL)
				return NULL;

			if (dir_list[0] == 0x00) {
				node = create_inode(filename, ic, ret, is_directory);
				if (node == NULL) 
					return NULL;

				dir_list[0] = ic;
				ret_ = file_write(ret, BLOCK_OFFSET+block_pointer*BLOCKSIZE, dir_list, BLOCKSIZE);

				// TODO: to a distinct fn
				++sb->inode_counter;
				ret_ = file_write(ret, sizeof(int), sb, sizeof(superblock_t));
				
				return node;
			} else {
				in *node = (in*) safe_alloc(sizeof(in));
				if (sb == NULL)
					return NULL;
				int zeropos = 0;
				for (i = 0; (i < DIR_LIST_SIZE); i++) {
					if (dir_list[i] == 0x00) {
						if (zeropos == 0)
							zeropos = i;
						continue;
					}
					ret_ = file_read(ret, INODE_OFFSET+sizeof(in)*dir_list[i], node, sizeof(in));
					if (!(strcmp(filename, node->filename))) {
						printk("File exists, returning\n");
						printk("found %s\n", node->filename);
						return node;
					}
				}
				i = zeropos;

				if (!(create))
					return NULL;

				// if mkdir, node->is_directory = 1
				
				node = create_inode(filename, ic, ret, is_directory);
				if (node == NULL)
					return NULL;
				dir_list[i] = node->inode_id;

				ret_ = file_write(ret, BLOCK_OFFSET+block_pointer*BLOCKSIZE, dir_list, BLOCKSIZE);

				// TODO: to a distinct fn
				++sb->inode_counter;
				ret_ = file_write(ret, sizeof(int), sb, sizeof(superblock_t));

				kfree(dir_list);

				return node; 
			}	
		} else {
			return root;
		}

	} else {
		// index first slash in path
		int index = (int)(slash_pos - path);

		// everything down the slash
		char *new_path = (char*) path+(sizeof(char)+index*sizeof(char));

		// everything before the slash
		char *before_path = (char*) safe_alloc(index);
		strlcpy(before_path, path, index+1);

		short *dir_list = safe_alloc(BLOCKSIZE);
		int ret_ = file_read(ret, BLOCK_OFFSET+BLOCKSIZE*(root->data[0]), dir_list, BLOCKSIZE);

		int found = 0;
		in *node = (in*) safe_alloc(sizeof(in));
		for (i = 0; (i < DIR_LIST_SIZE); i++) {
			if (dir_list[i] == 0x00)
				continue;
			ret_ = file_read(ret, INODE_OFFSET+sizeof(in)*dir_list[i], node, sizeof(in));
			if (!(strcmp(before_path, node->filename))) {
				found = 1;
				break;
			}
		}

		superblock_t *sb = (superblock_t*) safe_alloc(sizeof(superblock_t));
		if (sb == NULL)
			return NULL;
		ret_ = file_read(ret, sizeof(int), sb, sizeof(superblock_t));

		if (found) {
			return get_inode_rec(node, sb, ret, new_path, is_directory, create);
		} else {
			if (create) {
				int ic = sb->inode_counter;
				in *new_node = create_inode(before_path, ic, ret, is_directory);
				dir_list[i] = new_node->inode_id;
				ret_ = file_write(ret, BLOCK_OFFSET+BLOCKSIZE*(root->data[0]), dir_list, BLOCKSIZE);
				return get_inode_rec(new_node, sb, ret, new_path, is_directory, create);	
			} else {
				return NULL;
			}

		}

	}
	return 0x00;
}

in * create_inode(char *filename, int ic, struct file *ret, bool is_directory) {
	int ret_;

	in node = {
		.data = { 0 },
		.inode_id = ic,
		.is_directory = is_directory
	};

	in *node_ptr = (in*) safe_alloc(sizeof(in));
	if (node_ptr == NULL)
		return NULL;
	memcpy(node_ptr, &node, sizeof(in));

	strncpy(node.filename, filename, strlen(filename));
	ret_ = file_write(ret, (ic)*sizeof(in)+INODE_OFFSET, &node, sizeof(in));

	in *node_buf = (in*) kmalloc(sizeof(in), GFP_KERNEL);
	ret_ = file_read(ret, INODE_OFFSET+sizeof(in)*ic, node_buf, sizeof(in));

	return node_buf;
}

int write_to_file(in *node, char *data) {
	struct file *res = file_open(FILESYSTEM, O_RDWR, 0);
	int i, s, ret_ = 0;
	int b = node->data[0];

	for (s = 0; ((s < BLOCK_LIST_SIZE) && (node->data[s] != 0x00)); s++)
			;;
	for (i = 0; (i < strlen(data)*sizeof(char)); i+=BLOCKSIZE) {
		if (i/BLOCKSIZE >= s) {
			b = acquire_free_block(node);
		}
		ret_ += file_write(res, BLOCK_OFFSET+((short) b)*BLOCKSIZE, data+i, BLOCKSIZE);
	}

	file_close(res);
	return ret_;
}

char * read_from_file(in *node) {
	struct file *res = file_open(FILESYSTEM, O_RDWR, 0);
	int i, j, b, ret_ = 0;

	for (i = 0; (i < BLOCK_LIST_SIZE) && (node->data[i] != 0x00); ++i)
			;;
	printk("i is %d\n", node->data[i]);

	char *buf = (char*) safe_alloc(BLOCKSIZE*i);
	if (buf == NULL)
		return NULL;

	for (j = 0; j < i; j+=1) {
		b = node->data[j];
		ret_ += file_read(res, BLOCK_OFFSET+((short) b)*BLOCKSIZE, buf+BLOCKSIZE*j, BLOCKSIZE);
	}
	printk("from %s\n", node->filename);

	printk("read %d bytes \n", ret_);
	printk("content: %s \n", buf);

	file_close(res);

	if (!ret_)
		return NULL;

	return buf;
}

int remove_inode(in *node, in *parent) {
	if (unset_bitmap(BLOCK_MAP_OFFSET, BLOCK_MAP_SIZE, node->inode_id) == -1)
		return -1;

	in *node_buf = (in*) safe_alloc(sizeof(in));
	int i, ret_, found = 0;

	short *dir_list = safe_alloc(BLOCKSIZE);
	struct file *ret = file_open(FILESYSTEM, O_RDWR, 0);
	ret_ = file_read(ret, BLOCK_OFFSET+BLOCKSIZE*(parent->data[0]), dir_list, BLOCKSIZE);

	for (i = 0; (i < DIR_LIST_SIZE); i++) {
		if (dir_list[i] != 0x00) {
			ret_ = file_read(ret, INODE_OFFSET+sizeof(in)*dir_list[i], node_buf, sizeof(in));

			if (!(strcmp(node->filename, node_buf->filename))) {
				found = 1;
				break;
			}
		}
	}

	if (node_buf == NULL)
		return NULL;

	if (found) {
		dir_list[i] = 0x00;
		ret_ = file_write(ret, BLOCK_OFFSET+BLOCKSIZE*(parent->data[0]), dir_list, BLOCKSIZE);
	}
	
	file_close(ret);
	return 0;
}

int remove_file(char *path, bool is_directory) {
	char *slash_pos = strchr(path, '/');
	if ((strlen(path) == 1) && slash_pos)
		return -1;

	int index = (int)(slash_pos - path);
	char *parent_path = (char*) safe_alloc(index);
	strlcpy(parent_path, path, index);

	if (index == 0)
		parent_path = "/";

	in *parent_node = get_inode(parent_path, 1, 0);

	in *node = get_inode(path, is_directory, 0);
	free_blocks(node);
	remove_inode(node, parent_node);

	return 0;
}

int copy_file(char *old_path, char *new_path) {
	in *i_old = get_inode(old_path, 0, 0);
	in *i_new = get_inode(new_path, 0, 1);
	char *content = read_from_file(i_old);
	if (content && strlen(content))
		write_to_file(i_new, content);

	return 0;
}

int move_file(char *old_path, char *new_path) {
	copy_file(old_path, new_path);
	remove_file(old_path, 0);

	return 0;
}

static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset) {
	int ret_, i;
	in *node;

	for (i = 0; (i < len) && (i < BUF_LEN); i++)
		get_user(Message[i], buffer + i);
	
	if (Message[0] == 'a') {
		// touch

		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		get_inode(path, 0, 1);

		write_msg("success");

	} else if (Message[0] == '>') {
		// >

		// TODO: function of parsing touch message
		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		node = get_inode(path, 0, 0);
		if (!(node))
			return -1;

		char *data = (char*) safe_alloc(BUF_LEN);
		if (data == NULL)
			return -1;

		int j = 0;

		++i;
		while ((Message[i] != 0) && (i < BUF_LEN)) {
			data[j] = Message[i];
			++i;
			++j;
		}

		ret_ = write_to_file(node, data);

		kfree(data);

		write_msg("success");

	} else if (Message[0] == 'c') {
		// cat

		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		node = get_inode(path, 0, 0);
		if (!(node))
			return -1;

		char *content = read_from_file(node);
		content[strlen(content)] = '\n';
		//write_msg(data);

		write_msg(content);

	} else if (Message[0] == 'r') {
		// rm

		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		remove_file(path, 0);
		write_msg("success");

	} else if (Message[0] == 'p') {
		// cp file

		char m = Message[2];
		char path1[100] = { '\0' };
		char path2[100] = { '\0' };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path1[i-2] = m;
			++i;
			m = Message[i];
		}

		++i;
		m = Message[i];
		
		sscanf(Message+i, "%s", path2);

		copy_file(path1, path2);
		write_msg("success");

	} else if (Message[0] == 'v') {
		// mv

		char m = Message[2];
		char path1[100] = { '\0' };
		char path2[100] = { '\0' };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path1[i-2] = m;
			++i;
			m = Message[i];
		}

		++i;
		m = Message[i];
		
		sscanf(Message+i, "%s", path2);
		
		if (!(node))
			return -1;

		move_file(path1, path2);
		write_msg("success");
	} else if (Message[0] == 'd') {
		// cd

		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		node = get_inode(path, 1, 0);
		printk("inode %p\n", node);
		if (!(node)) {
			printk("no node!\n");
			write_msg("failure");
			return -1;
		}
		path[strlen(path)] = '\n';

		write_msg(path);
		kfree(node);

	} else if (Message[0] == 's') {
		// ls

		struct file *res = file_open(FILESYSTEM, O_RDWR, 0);

		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		in *node = get_inode(path, 1, 0);
		if (node == NULL) {
			file_close(res);
			return -1;
		}

		short *dir_list = (short*) safe_alloc(BLOCKSIZE);
		ret_ = file_read(res, BLOCK_OFFSET+node->data[0]*BLOCKSIZE, dir_list, BLOCKSIZE);
		if (!(node))
			return -1;

		node = (in*) safe_alloc(sizeof(in));
		char *msg = (char*) safe_alloc(sizeof(char)*2000);
		sprintf(msg, "empty");

		int ret_msg = 0;

		char *num_buff = (char*) safe_alloc(sizeof(char)*100);
		for (i = 0; (i < DIR_LIST_SIZE); i++) {
			sprintf(num_buff, "%d", dir_list[i]);
			if (num_buff[0] == '0') {
				continue;
			}
			ret_ = file_read(res, INODE_OFFSET+sizeof(in)*dir_list[i], node, sizeof(in));
			printk("%s ", node->filename);
			ret_msg += sprintf(msg+ret_msg, "%s\n", node->filename);
			ret_msg += 1;
		}
		write_msg(msg);

		file_close(res);

	} else if (Message[0] == 'i') {
		// mkdir -p

		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		get_inode(path, 1, 1);

		write_msg("success");

	} else if (Message[0] == 'd') {
		char m = Message[2];
		char path[100] = { 0x00 };
		i = 2;

		while ((ispunct(m) || isalpha(m)) && (i < BUF_LEN)) {
			path[i-2] = m;
			++i;
			m = Message[i];
		}

		node = get_inode(path, 1, 0);

		if (node == NULL) {
			write_msg("failure");
			return -1;
		}
		write_msg(path);
	}

	Message_Ptr = Message;

	kfree(node);

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
