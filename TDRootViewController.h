#import <UIKit/UIKit.h>

@interface TDRootViewController : UITableViewController

@property (nonatomic, strong) NSArray *apps;
@property (nonatomic, strong) NSUserDefaults *hookPrefs;
@property (nonatomic, strong) NSMutableDictionary *iconCache;

@end

